
rule Trojan_Win32_Unruy_GZY_MTB{
	meta:
		description = "Trojan:Win32/Unruy.GZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {0e 34 6b c0 12 fc 4e 46 09 27 } //05 00 
		$a_03_1 = {8a 66 7b f3 91 ba 90 01 04 34 e9 13 26 01 56 7b 1b 70 71 30 3a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}