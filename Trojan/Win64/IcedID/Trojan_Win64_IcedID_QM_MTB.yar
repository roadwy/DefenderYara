
rule Trojan_Win64_IcedID_QM_MTB{
	meta:
		description = "Trojan:Win64/IcedID.QM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_00_0 = {69 f6 01 01 00 00 4d 03 f3 0f b6 c0 03 f0 c1 e0 10 33 f0 41 8a 06 84 c0 } //10
		$a_81_1 = {41 4c 45 78 72 5a 74 78 42 4a 6c 44 57 46 6b 6c 75 43 70 } //3 ALExrZtxBJlDWFkluCp
		$a_81_2 = {46 64 51 6f 6f 42 77 73 79 54 4c 75 6c 65 58 50 6a 6d 4b 71 77 } //3 FdQooBwsyTLuleXPjmKqw
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3) >=16
 
}
rule Trojan_Win64_IcedID_QM_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.QM!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 48 b9 0a 01 00 00 2b c8 8b 45 48 2b c8 41 03 cc 89 4d 48 8a 45 50 88 02 44 89 4d 48 44 89 55 50 8b 45 48 41 23 c6 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}