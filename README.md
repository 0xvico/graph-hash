# Graph Hash


## About
This is a PoC of Graph Hash. We try to use Graph Hash to do,
- **Malware Classification**
- **Threat Intelligence Exchange**

There are more details in "[Publications](#Publications)" section.


## PoC
We implement the concept as an IDA Pro plugin.

The development environment includes,
- IDA Pro 7.2
- IDApython
- MD5
- ssdeep


## Batch Script
The batch script, gh-batch.py, help to calculate the graph hash of multiple samples.

Here is an example.
```
python.exe gh-batch.py --ida=C:\IDA_v7.2.181105\idat.exe --sample=C:\sample
```

Options,
```
--ida      The path of the text-mode IDA Pro
--sample   The path of samples
```


## Publications
- Chia-Ching Fang and Shih-Hao Weng, [What Species of Fish Is This? Malware Classification with Graph Hash](https://gsec.hitb.org/sg2019/sessions/what-species-of-fish-is-this-malware-classification-with-graph-hash/), HITB GSEC 2019, August 2019. [Slide](https://gsec.hitb.org/materials/sg2019/D1%20-%20What%20Species%20of%20Fish%20Is%20This%20-%20Malware%20Classification%20with%20Graph%20Hash%20-%20Chia%20Ching%20Fang%20&%20Shih-Hao%20Weng.pdf) and [Video](https://www.youtube.com/watch?v=ATyoTmhzAPM)
- Chia-Ching Fang and Shih-Hao Weng, [Malware Classification with Graph Hash, Applied to the Orca Cyberespionage Campaign](https://blog.trendmicro.com/trendlabs-security-intelligence/malware-classification-with-graph-hash-applied-to-the-orca-cyberespionage-campaign/), Trend Micro, September 2019.

