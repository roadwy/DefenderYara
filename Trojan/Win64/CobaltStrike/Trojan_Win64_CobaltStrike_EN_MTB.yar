
rule Trojan_Win64_Cobaltstrike_EN_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c1 c1 f9 1f 29 ca 6b ca 36 29 c8 89 c2 89 d0 83 c0 38 44 89 c1 31 c1 48 8b 95 10 03 00 00 8b 85 04 03 00 00 48 98 88 0c 02 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Cobaltstrike_EN_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 89 cb 49 89 d2 31 c9 4c 39 c9 73 90 01 01 48 89 c8 31 d2 49 f7 f2 41 8a 04 13 41 30 04 08 48 8b 05 90 01 04 48 c1 e0 04 48 8d 4c 01 01 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Cobaltstrike_EN_MTB_3{
	meta:
		description = "Trojan:Win64/Cobaltstrike.EN!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 63 c8 41 8d 40 82 41 ff c0 30 44 0c 28 41 83 f8 0c 72 ec } //1
		$a_01_1 = {57 69 6e 64 6f 77 73 50 72 6f 6a 65 63 74 5f 62 69 6e 2e 64 6c 6c } //1 WindowsProject_bin.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}