
rule Trojan_Win32_VidarCrypt_PAA_MTB{
	meta:
		description = "Trojan:Win32/VidarCrypt.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 00 e1 34 ef c6 c3 01 08 c3 55 8b ec 81 ec e8 0a 00 00 8b 45 08 } //01 00 
		$a_03_1 = {d3 e6 8b 4d f4 8b c2 d3 e8 03 b5 90 01 04 89 45 fc 8b 85 90 01 04 01 45 fc 8d 04 17 33 f0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}