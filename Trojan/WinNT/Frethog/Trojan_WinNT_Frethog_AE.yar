
rule Trojan_WinNT_Frethog_AE{
	meta:
		description = "Trojan:WinNT/Frethog.AE,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 7d f0 4d 5a 91 11 75 07 c6 05 90 01 02 01 00 01 81 7d f0 4b 43 55 46 75 07 c6 05 90 01 02 01 00 00 33 c9 8a 0d 90 01 02 01 00 85 c9 75 09 81 7d f0 4b 43 55 46 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}