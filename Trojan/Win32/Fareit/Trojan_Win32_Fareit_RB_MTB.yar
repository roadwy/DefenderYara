
rule Trojan_Win32_Fareit_RB_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 56 57 8d 3d 90 01 04 8b 75 08 ac 34 37 aa 3c 00 75 f8 5f 5e c9 c2 04 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Fareit_RB_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 10 6b c0 22 6b f6 22 89 45 fc 2b 83 48 02 00 00 83 e8 21 50 } //1
		$a_01_1 = {6a 22 5b 89 45 08 8b 45 e0 99 f7 f9 8b c8 8b 45 e4 99 f7 fb 89 45 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}