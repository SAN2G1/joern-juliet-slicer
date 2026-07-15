# joern-juliet-slicer

쉽게 따라하는 Joern juliet slicer 사용기 

1. java 17을 깐다. 
2. java_sard_source_sink 파일을 프로젝트에 가져온다. 
3. joern은 설치해두고 joern이 설치된 폴더를 기억해둔다. 
4. setting.sh 파일에 상단의 환경 변수 내용을 수정한다. 
5. setting.sh 파일에 `chmod u+x` 명령을 주어 실행권한을 부여한다. 
6. ./setting.sh 파일을 실행한다. 
7. flow_filter.py 
8. `python3 cpg_builder.py output/filtered_source_sink_dataset/cwe15_source_sink_classified.xml`

``` bash
swlab@swlab:~/Documents/swvul/joern-juliet-slicer$ python3 cpg_builder.py     output/filtered_source_sink_dataset/cwe15_source_sink_classified.xml
CWE               : 15
Filtered XML      : /home/swlab/Documents/swvul/joern-juliet-slicer/output/filtered_source_sink_dataset/cwe15_source_sink_classified.xml
Testcases         : 444
Flows             : 1066
Unique Java files : 708
CPG output dir    : /home/swlab/Documents/swvul/joern-juliet-slicer/output/CPG/cwe15_cpg
[147/444 |  33.1%] testcase 147: building (2 files, 2 flows)
```