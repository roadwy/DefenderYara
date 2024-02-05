
rule Trojan_Win32_Boxter_CA_MTB{
	meta:
		description = "Trojan:Win32/Boxter.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 6c 24 3c 0f be 5d 00 33 5c 24 30 53 8b 6c 24 40 58 88 45 00 8b 5c 24 3c 43 89 5c 24 3c ff 44 24 28 0f } //05 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 39 65 63 63 2d 32 33 2d 32 34 33 2d 39 39 2d 31 38 36 2e 6e 67 72 6f 6b 2e 69 6f } //00 00 
	condition:
		any of ($a_*)
 
}