
rule Trojan_BAT_DarkTortilla_ZMU_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZMU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {26 1f 0b 13 06 2b bd 02 28 ?? 01 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 07 75 0d 00 00 1b 8e 69 17 da 0c 19 13 06 2b 9c 16 0d 1a 13 06 2b 95 07 75 0d 00 00 1b 09 91 16 fe 01 13 04 11 04 2c 08 } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}