
rule Trojan_BAT_DarkTortilla_MZL_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.MZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 09 13 06 2b bd 02 28 ?? ?? 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 07 75 0d 00 00 1b 8e 69 17 da 0c 1b 13 06 2b 9c 16 0d 17 13 06 2b 95 07 74 0d 00 00 1b 09 91 16 fe 01 13 04 11 04 2c 08 } //5
		$a_01_1 = {07 75 0d 00 00 1b 0a 06 75 0d 00 00 1b 7e 86 00 00 04 1f 65 7e 86 00 00 04 1f 65 91 7e 13 01 00 04 1f 11 93 59 1f 7a 5f 9c 2a } //4
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}