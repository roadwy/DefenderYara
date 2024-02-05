
rule Trojan_Win32_Glupteba_NL_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {50 8b 45 ec 90 18 55 8b ec 33 45 08 5d c2 90 00 } //01 00 
		$a_02_1 = {50 8b 45 ec e8 90 02 04 81 3d 90 02 08 8b 90 02 03 75 90 00 } //03 00 
		$a_02_2 = {50 8b 45 ec e8 90 02 04 81 3d 90 02 08 8b 90 02 03 90 18 33 90 02 03 83 90 02 06 89 90 02 03 8b 90 02 03 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}