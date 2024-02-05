
rule Trojan_Win32_Zloader_SIBF_MTB{
	meta:
		description = "Trojan:Win32/Zloader.SIBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b d6 8b 74 24 90 01 01 83 44 24 90 01 02 8b 06 05 90 01 04 89 06 90 00 } //01 00 
		$a_02_1 = {8b d8 8a 81 90 01 04 8d 49 01 4e 90 02 30 85 f6 75 90 00 } //01 00 
		$a_02_2 = {8b 4d 08 89 4d 90 01 01 8b 15 90 01 04 83 c2 90 01 01 2b 55 90 01 01 33 c0 89 15 90 01 04 a3 90 01 04 68 90 01 04 8b 4d 90 01 01 51 68 90 01 04 8b 55 90 1b 00 52 ff 15 90 01 04 90 08 00 30 ff 65 90 1b 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}