
rule Trojan_AndroidOS_FakeInst_GA{
	meta:
		description = "Trojan:AndroidOS/FakeInst.GA,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 43 2f 42 65 71 74 2f 6d 71 66 2f 49 43 69 48 75 73 79 6c 75 68 3b } //01 00  seC/Beqt/mqf/ICiHusyluh;
		$a_01_1 = {51 42 71 68 43 48 75 73 75 79 6c 75 68 3b } //01 00  QBqhCHusuyluh;
		$a_01_2 = {70 71 79 64 51 66 66 42 79 73 71 6a 79 65 64 3b } //00 00  pqydQffBysqjyed;
	condition:
		any of ($a_*)
 
}