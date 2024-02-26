
rule Trojan_Win32_Zenpak_N_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 7d e8 0f b6 3c 0f 01 df 8b 5d ec 0f b6 14 13 01 d7 89 3d 98 78 0d 10 89 f8 99 8b 7d d4 f7 ff } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpak_N_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 75 d0 32 0c 32 8b 55 90 01 01 88 0c 32 90 00 } //02 00 
		$a_01_1 = {8b 12 0f b7 37 31 d6 01 ce } //02 00 
		$a_01_2 = {8b 12 8b 3f 0f b7 1b 31 d3 } //00 00 
	condition:
		any of ($a_*)
 
}