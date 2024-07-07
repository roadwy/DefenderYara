
rule Backdoor_Win32_Remcos_ARK_MTB{
	meta:
		description = "Backdoor:Win32/Remcos.ARK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d a4 24 00 00 00 00 90 02 1f 8b 90 01 02 40 24 41 00 33 90 01 02 89 90 02 02 85 c9 74 90 02 04 83 c1 01 90 00 } //1
		$a_03_1 = {8d a4 24 00 00 00 00 90 02 1f 8b 90 01 02 70 24 41 00 33 90 01 02 85 c9 89 90 02 02 74 90 02 04 83 c1 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule Backdoor_Win32_Remcos_ARK_MTB_2{
	meta:
		description = "Backdoor:Win32/Remcos.ARK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f0 8b 45 ec e8 90 01 04 8b d8 85 db 75 90 01 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 8b c6 8b 55 e8 e8 90 01 04 eb 90 01 01 ff 36 90 0a ef 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}