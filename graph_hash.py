import idc
import idautils
import idaapi
import sys
import os
import hashlib
try:
    import ssdeep
except:
    pass

class CallGraph:
    def __init__(self): 
        self.num_func = 0
        self.graph_pattern = ''
        self.roots = []
        self.vertices = {}
        self.min_ea = idaapi.cvar.inf.minEA
        self.max_ea = idaapi.cvar.inf.maxEA
        self.ea_size = self.max_ea - self.min_ea

    def add_vertex(self, ea, func_type):
        address_block = (ea - self.min_ea) * 16 / self.ea_size
        vertex_value = chr(address_block) + chr(func_type)
        self.vertices[ea] = {'index': self.num_func, 'func_type': func_type, 'value': vertex_value, 'targets': [], 'is_visited': 0}
        self.num_func += 1

    def add_root(self, ea):
        self.roots.append(ea)

    def set_roots(self):
        for ea in self.vertices:
            for target_ea in self.vertices[ea]['targets']:
                if target_ea in self.roots:
                    self.roots.remove(target_ea)

    def set_value(self):
        for ea in self.vertices:
            address_block = (ea - self.min_ea) * 16 / self.ea_size
            func_type = self.vertices[ea]['func_type']
            self.vertices[ea]['value'] = chr(address_block) + chr(func_type)

    def connect_vertex(self, source_ea, target_ea):
        if not target_ea in self.vertices[source_ea]['targets']:
            self.vertices[source_ea]['targets'].append(target_ea)
      
    def build_graph_pattern(self, vertex):
        self.graph_pattern += self.vertices[vertex]['value']
        if self.vertices[vertex]['is_visited'] == 0:
            self.vertices[vertex]['is_visited'] = 1
            for target_ea in self.vertices[vertex]['targets']:
                self.build_graph_pattern(target_ea)

    def get_graph_md5(self):
        m = hashlib.md5()
        m.update(self.graph_pattern)
        return m.hexdigest()

    def get_graph_sha1(self):
        m = hashlib.sha1()
        m.update(self.graph_pattern)
        return m.hexdigest()

    def get_graph_sha256(self):
        m = hashlib.sha256()
        m.update(self.graph_pattern)
        return m.hexdigest()

    def get_graph_ssdeep(self):
        if 'ssdeep' in sys.modules:
            return ssdeep.hash(self.graph_pattern)
        else:
            return 'No ssdeep Modules. Please Install ssdeep.'


def main():
    imp_funcs = []
    xrefs = []
    cg = CallGraph()
    file_name = idc.get_root_filename()
    file_path = idc.GetInputFilePath()

    def get_file_ssdeep():
        if 'ssdeep' in sys.modules:
            return ssdeep.hash_from_file(file_path)
        else:
            return 'No ssdeep Modules. Please Install ssdeep.'

    def imp_cb(ea, name, ord):
        imp_funcs.append(ea)
        return True

    if 'batch' in idc.ARGV:
        idaapi.autoWait()

    for fea in Functions():
        func_flags = get_func_flags(fea)
        # NORMAL = 0
        # LIBRARY = 1
        # IMPORTED = 2
        # THUNK = 3
        if func_flags & FUNC_LIB:
            func_type = 1
        elif func_flags & FUNC_THUNK:
            func_type = 3
        else:
            func_type = 0

        cg.add_vertex(fea, func_type)
        cg.add_root(fea)

        items = FuncItems(fea)
        for item in items:
            for xref in XrefsFrom(item, 0):
                # https://www.hex-rays.com/products/ida/support/idadoc/313.shtml
                if xref.type != fl_F:
                    xrefs.append([fea, xref.to])

    # List Import Functions and Add to cg
    num_imp_module = idaapi.get_import_module_qty()
    for i in range(0, num_imp_module):
        idaapi.enum_import_names(i, imp_cb)
    imp_funcs.sort()
    for imp_func_ea in imp_funcs:
        cg.add_vertex(imp_func_ea, 2)

    for xref in xrefs:
        if xref[1] in cg.vertices:
            cg.connect_vertex(xref[0], xref[1])

    cg.set_roots()

    for root in cg.roots:
        cg.build_graph_pattern(root)

    if len(idc.ARGV) == 0:
        print('Graph MD5: %s' % cg.get_graph_md5())
        print('Graph SHA1: %s' % cg.get_graph_sha1())
        print('Graph SHA256: %s' % cg.get_graph_sha256())
        print('Graph SSDEEP: %s' % cg.get_graph_ssdeep())
        print('File SSDEEP: %s' % get_file_ssdeep())

    if 'out_pattern' in idc.ARGV:
        if not os.path.isdir('./out'):
            os.mkdir('./out')
        f = open('./out/' + file_name + '.bin', 'wb')
        f.write(cg.graph_pattern)
        f.close()

    if 'batch' in idc.ARGV:
        if not os.path.isdir('./out'):
            os.mkdir('./out')
        f = open('./out/result', 'a+')
        f.write('%s,%s,%s,%s\n' % (file_name, cg.get_graph_md5(), cg.get_graph_ssdeep(), get_file_ssdeep()))
        f.close()
        idc.Exit(0)

if __name__ == '__main__':
    main()