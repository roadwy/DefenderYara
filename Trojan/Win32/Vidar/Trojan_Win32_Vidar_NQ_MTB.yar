
rule Trojan_Win32_Vidar_NQ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.NQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {87 d5 7c 3a 81 44 24 90 01 01 8c eb 73 22 8b 4c 24 10 8b d7 8b 5c 24 90 01 01 8b c7 d3 e2 03 54 24 1c c1 e8 90 01 01 03 44 24 34 33 d0 c7 05 90 01 08 8d 04 2f 33 d0 2b da 8b 15 90 01 04 89 5c 24 14 81 fa 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}