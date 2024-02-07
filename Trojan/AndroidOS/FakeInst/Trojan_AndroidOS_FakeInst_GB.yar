
rule Trojan_AndroidOS_FakeInst_GB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.GB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 43 2f 69 75 73 6b 68 79 6a 4f 2f 69 75 68 6c 79 73 75 2f 68 75 73 75 79 6c 75 68 2f 48 75 72 65 65 6a 48 75 73 75 79 6c 75 68 3b } //01 00  seC/iuskhyjO/iuhlysu/husuyluh/HureejHusuyluh;
		$a_01_1 = {55 6a 77 78 6e 78 79 6a 73 68 6a 52 66 73 66 6c 6a 77 2e 6f 66 61 66 } //01 00  UjwxnxyjshjRfsfljw.ofaf
		$a_01_2 = {53 65 64 69 6a 71 64 6a 69 3b } //00 00  Sedijqdji;
	condition:
		any of ($a_*)
 
}