
rule Trojan_Win32_Zenpak_L_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {31 c2 42 8d 05 90 01 04 01 38 83 ea 04 89 d0 48 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpak_L_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 7d e8 0f b6 1c 07 01 f3 89 45 d4 31 f6 89 55 d0 89 f2 8b 75 f0 f7 f6 8b 75 ec 0f b6 14 16 01 d3 89 d8 99 8b 5d d0 f7 fb } //00 00 
	condition:
		any of ($a_*)
 
}