
rule Trojan_BAT_Urelas_SP_MTB{
	meta:
		description = "Trojan:BAT/Urelas.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {11 06 17 8d 33 00 00 01 25 16 1f 20 9d 6f 90 01 03 0a 13 08 00 11 08 13 09 16 13 0a 38 8a 00 00 00 11 09 11 0a 9a 13 0b 11 0b 72 35 a2 00 70 6f 90 01 03 0a 13 0c 11 0c 2c 6b 00 11 0b 28 90 01 03 06 13 0d 06 11 0d 6f 90 01 03 0a 2d 0e 11 0d 72 27 a2 00 70 28 90 01 03 0a 90 00 } //01 00 
		$a_01_1 = {72 00 75 00 6e 00 6f 00 73 00 2e 00 65 00 78 00 65 00 } //01 00  runos.exe
		$a_01_2 = {69 6f 6d 44 6f 6d 65 2e 70 64 62 } //00 00  iomDome.pdb
	condition:
		any of ($a_*)
 
}