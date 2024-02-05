
rule Trojan_Win32_AveMaria_DSK_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {8a 57 01 48 30 17 4f 85 c0 7d } //01 00 
		$a_00_1 = {8a 28 47 8a 0a 4b 88 08 40 88 2a 4a eb } //02 00 
		$a_02_2 = {8b 45 f4 03 45 fc 0f be 08 8b 55 e0 0f be 82 90 01 04 33 c8 8b 55 f4 03 55 fc 88 0a eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}