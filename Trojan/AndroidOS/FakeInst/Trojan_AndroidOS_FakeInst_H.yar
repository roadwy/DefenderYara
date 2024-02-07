
rule Trojan_AndroidOS_FakeInst_H{
	meta:
		description = "Trojan:AndroidOS/FakeInst.H,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 43 2f 43 43 69 2f 72 77 2f 6a 68 71 64 69 71 73 6a 79 65 64 2f 46 68 79 6c 79 42 75 77 75 74 49 43 69 48 75 73 75 79 6c 75 68 3b } //01 00  seC/CCi/rw/jhqdiqsjyed/FhylyBuwutICiHusuyluh;
		$a_01_1 = {2f 73 78 79 64 71 43 65 72 79 42 75 31 30 30 38 36 2f 6b 6a 79 42 69 2f 6f 75 66 78 65 64 75 49 6b 66 66 65 68 6a 3b } //01 00  /sxydqCeryBu10086/kjyBi/oufxeduIkffehj;
		$a_01_2 = {56 71 6e 75 6f 71 64 6b 73 78 75 68 51 73 6a 79 6c 79 6a 4f } //00 00  VqnuoqdksxuhQsjylyjO
	condition:
		any of ($a_*)
 
}