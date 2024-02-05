
rule Trojan_Win32_Emotet_DAS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 56 6a 00 6a 01 55 8b f8 53 ff d7 85 c0 90 13 8b 06 90 02 03 50 e8 90 01 04 8b 4c 24 90 01 01 83 c4 04 6a 00 6a 00 56 50 6a 01 55 53 89 01 ff d7 5f 5e 90 00 } //01 00 
		$a_02_1 = {68 e0 07 00 00 03 ca 51 50 89 44 24 90 01 01 ff d7 8b 44 24 90 01 01 83 c4 0c 6a 00 6a 40 68 00 30 00 00 50 6a 00 55 ff d3 8b 90 01 07 51 8b f0 52 56 ff d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}