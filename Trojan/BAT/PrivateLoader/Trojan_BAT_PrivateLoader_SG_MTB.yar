
rule Trojan_BAT_PrivateLoader_SG_MTB{
	meta:
		description = "Trojan:BAT/PrivateLoader.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {16 13 0a 2b 33 11 08 11 0a 8f 1a 00 00 01 25 71 1a 00 00 01 08 d2 61 d2 81 1a 00 00 01 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 08 8e 69 32 c5 } //01 00 
		$a_00_1 = {53 00 63 00 72 00 75 00 62 00 43 00 72 00 79 00 70 00 74 00 2e 00 65 00 78 00 65 00 } //00 00  ScrubCrypt.exe
	condition:
		any of ($a_*)
 
}