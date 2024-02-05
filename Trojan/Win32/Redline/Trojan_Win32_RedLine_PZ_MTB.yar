
rule Trojan_Win32_RedLine_PZ_MTB{
	meta:
		description = "Trojan:Win32/RedLine.PZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 fe f8 6a 1a 01 0f 8d 90 01 04 c7 44 24 90 01 01 7b 83 66 09 c7 84 24 90 01 04 43 a8 44 1c c7 84 24 90 01 04 31 d7 5f 47 c7 44 24 90 01 01 75 45 68 6d c7 84 24 90 01 04 22 e9 77 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}