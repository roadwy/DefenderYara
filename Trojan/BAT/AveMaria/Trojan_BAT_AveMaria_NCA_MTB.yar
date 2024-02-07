
rule Trojan_BAT_AveMaria_NCA_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {25 16 02 8c 5c 00 00 01 a2 25 0b 14 14 17 8d 90 01 03 01 25 16 17 9c 25 0c 28 90 01 03 0a 0d 1a 13 05 38 90 01 03 ff 08 74 90 01 03 1b 16 91 2d 08 19 13 05 38 90 01 03 ff 1e 2b f6 1d 13 05 38 90 01 03 ff 07 74 90 01 03 1b 16 9a 28 90 01 03 0a d0 90 01 03 01 28 90 01 03 0a 28 90 01 03 0a a5 90 01 03 01 90 00 } //01 00 
		$a_01_1 = {36 66 34 62 65 64 63 62 35 31 37 30 36 37 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00  6f4bedcb517067.Resources.resources
	condition:
		any of ($a_*)
 
}