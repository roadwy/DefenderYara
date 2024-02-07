
rule Trojan_AndroidOS_FakeInst_G{
	meta:
		description = "Trojan:AndroidOS/FakeInst.G,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 43 2f 71 64 74 68 65 79 74 2f 43 71 79 64 2f 49 43 69 48 75 73 75 79 6c 75 68 3b } //01 00  seC/qdtheyt/Cqyd/ICiHusuyluh;
		$a_01_1 = {2f 52 71 69 75 51 6b 6a 78 75 64 79 73 71 6a 79 65 64 58 6a 6a 66 53 42 79 75 64 6a 3b } //01 00  /RqiuQkjxudysqjyedXjjfSByudj;
		$a_01_2 = {72 68 65 71 74 73 71 69 6a 48 75 73 75 79 6c 75 68 6d 68 79 6a 75 } //01 00  rheqtsqijHusuyluhmhyju
		$a_01_3 = {4a 51 44 53 51 73 6a 79 6c 79 6a 4f } //00 00  JQDSQsjylyjO
	condition:
		any of ($a_*)
 
}