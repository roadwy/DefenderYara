
rule Trojan_AndroidOS_FakeInst_GC{
	meta:
		description = "Trojan:AndroidOS/FakeInst.GC,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 73 65 43 2f 43 65 72 73 42 79 73 6e 2f 71 64 74 68 65 79 74 2f 4b 43 75 64 77 56 75 75 74 72 71 73 6e 3b } //1 LseC/CersBysn/qdtheyt/KCudwVuutrqsn;
		$a_01_1 = {52 66 6e 73 46 68 79 6e 61 6e 79 64 2e 6f 66 61 66 } //1 RfnsFhynanyd.ofaf
		$a_01_2 = {4c 73 64 2f 73 65 43 2f 77 6d 2f 42 79 6c 75 6d 71 42 42 66 71 66 75 68 5f 4f 73 6a 2f 62 53 4a 42 79 6c 75 4d 71 42 42 66 71 66 75 68 3b } //1 Lsd/seC/wm/BylumqBBfqfuh_Osj/bSJByluMqBBfqfuh;
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}