
rule Trojan_Win64_IcedId_AMT_MTB{
	meta:
		description = "Trojan:Win64/IcedId.AMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {68 6f 70 65 72 64 } //hoperd  3
		$a_80_1 = {6b 6f 6d 70 77 } //kompw  3
		$a_80_2 = {70 61 72 61 6d 74 } //paramt  3
		$a_80_3 = {53 65 6e 64 4d 65 73 73 61 67 65 41 } //SendMessageA  3
		$a_80_4 = {47 65 74 4d 65 73 73 61 67 65 57 } //GetMessageW  3
		$a_80_5 = {44 69 73 70 61 74 63 68 4d 65 73 73 61 67 65 57 } //DispatchMessageW  3
		$a_80_6 = {53 79 73 74 65 6d 50 61 72 61 6d 65 74 65 72 73 49 6e 66 6f 57 } //SystemParametersInfoW  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}
rule Trojan_Win64_IcedId_AMT_MTB_2{
	meta:
		description = "Trojan:Win64/IcedId.AMT!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 81 ec 38 01 00 00 bb 10 80 27 00 48 8d 74 24 20 89 1e 89 5c 24 28 f2 0f 2a 44 24 28 48 8d 7c 24 30 f2 0f 11 07 } //10
		$a_01_1 = {48 81 ec 58 01 00 00 be b7 c1 27 00 89 74 24 2c 89 74 24 28 f2 0f 2a 44 24 28 f2 0f 11 44 24 30 89 74 24 2c 89 74 24 28 0f 57 c0 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}