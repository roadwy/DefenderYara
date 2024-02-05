
rule Trojan_Win32_AveMaria_GA_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 0c d0 f7 d1 8b 55 90 01 01 03 55 90 01 01 88 0a 90 13 90 02 20 8b 45 90 01 01 83 c0 90 01 01 89 45 90 01 01 8b 4d 90 01 01 83 e9 90 01 01 39 4d 90 02 25 8b 55 90 01 01 83 ea 90 01 01 2b 55 90 01 01 8b 85 90 00 } //01 00 
		$a_02_1 = {0f be 02 8b 8d 90 02 20 0f be 54 0d 90 01 01 33 c2 8b 4d 90 01 01 03 4d 90 01 01 88 01 90 13 90 02 20 8b 45 90 01 01 83 c0 90 01 01 89 45 90 01 01 8b 4d 90 01 01 3b 8d 90 02 20 8b 45 90 02 30 89 95 90 02 20 8b 55 90 01 01 03 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}