
rule Trojan_BAT_Growtopia_LF_MTB{
	meta:
		description = "Trojan:BAT/Growtopia.LF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 02 14 fe 01 0d 09 2c 05 14 13 04 2b 47 03 14 fe 01 13 05 11 05 2c 07 7e 11 00 00 0a 10 01 02 28 17 00 00 0a 0a 28 12 00 00 0a 03 6f 13 00 00 0a 0b 28 14 00 00 0a 07 6f 15 00 00 0a 0b 06 07 28 04 00 00 06 0c 28 12 00 00 0a 08 6f 18 00 00 0a 13 04 2b 00 11 04 2a } //01 00 
		$a_00_1 = {00 28 2c 00 00 0a 00 16 28 2d 00 00 0a 00 00 28 06 00 00 06 00 72 01 00 00 70 72 33 00 00 70 28 02 00 00 06 72 3f 00 00 70 72 33 00 00 70 28 02 00 00 06 16 1f 10 28 2e 00 00 0a 26 00 de 05 26 00 00 de 00 2a } //01 00 
		$a_80_2 = {47 72 6f 77 74 6f 70 69 61 54 72 61 69 6e 65 72 } //GrowtopiaTrainer  01 00 
		$a_80_3 = {73 6d 74 70 2e 67 6d 61 69 6c 2e 63 6f 6d } //smtp.gmail.com  01 00 
		$a_80_4 = {53 61 76 65 2e 64 61 74 20 6e 6f 74 20 66 6f 75 6e 64 } //Save.dat not found  00 00 
	condition:
		any of ($a_*)
 
}