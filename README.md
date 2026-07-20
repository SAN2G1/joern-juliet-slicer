# joern-juliet-slicer

쉽게 따라하는 Joern juliet slicer 사용기 

1. java 17을 깐다. 
2. java_sard_source_sink 파일을 프로젝트 루트에 가져온다. (이건 이미 xml 추출 다해놔서 안해도 됩니다)
3. joern은 설치해두고 joern이 설치된 폴더를 기억해둔다. (**매우 중요 절대 경로 가져올 것**) 
4. setting.sh 파일에 상단의 환경 변수 내용을 자신의 환경에 맞게 수정 한다. 
   script/run_pdg_slice.sh 을 실행할 때 환경 변수 PATH를 joern-cli에 맞게 수정 한다.(joern/joern-cli 으로 끝나는거)
   못찾겠으면 루트에서 `find -name joern-cli`로 찾으면 됩니다. 
```
swlab@swlab:~/Documents/swvul$ find -name joern-cli
./joern/joern-cli  <---- 요거
./joern/joern-cli/bin/joern-cli
swlab@swlab:~/Documents/swvul$ 
```
이렇게 두개가 나오면 짧은거 선택하면 되요 **절대 경로로 넣어야 해요**

5. setting.sh 파일에 `chmod u+x` 명령을 주어 실행권한을 부여한다. 
6. ./setting.sh 파일을 실행한다. 
7. flow_filter.py  (이건 해둠 결과가 output/filtered_sourc... 에 있어요)
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

9. `python3 batch_slicer.py output/CPG/cwe15_cpg` 이렇게 하면 되고 뒤에 폴더만 바꿔주면 되요(자동화 스크립트 만들면 편할 것 같아요) 

10. 끝! 마지막에 결과가 output/slice/cwe.. 저장됩니다!

