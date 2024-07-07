
rule Trojan_Win32_Zenpak_M_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 75 e8 0f b6 3c 0e 01 c7 89 c8 31 db 89 55 d8 89 da 8b 5d f0 f7 f3 8b 75 ec 0f b6 14 16 01 d7 89 f8 99 8b 7d d8 f7 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_M_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 fa 81 c2 90 01 04 0f b7 12 31 f2 01 ca 05 90 00 } //2
		$a_03_1 = {01 da 81 c2 90 01 04 0f b7 12 31 f2 8b 75 90 00 } //2
		$a_03_2 = {8a 1c 31 32 1c 17 8b 55 90 01 01 88 1c 32 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=2
 
}