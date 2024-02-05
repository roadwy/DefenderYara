
rule Trojan_Win32_AveMaria_MS_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c0 01 89 45 90 01 01 8b 4d 8c 83 e9 01 39 4d 90 01 01 7f 33 8b 55 8c 83 ea 01 2b 55 90 01 01 8b 85 90 02 04 8b 0c 90 01 01 f7 d1 89 8d 90 02 04 83 bd 90 02 05 74 0e 8b 55 84 03 55 90 01 01 8a 85 90 02 04 88 02 eb b9 90 00 } //01 00 
		$a_02_1 = {83 c2 01 89 90 02 02 8b 90 02 02 3b 90 02 05 7d 90 01 01 8b 90 02 02 99 f7 90 02 05 89 90 02 05 8b 90 02 02 03 90 02 02 0f 90 02 04 8b 90 02 05 0f 90 02 04 33 90 01 01 8b 90 02 02 03 90 02 02 88 10 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}