
rule Trojan_BAT_OceanDrive_B_dha{
	meta:
		description = "Trojan:BAT/OceanDrive.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 d4 01 00 70 0a 1b 8d 11 00 00 01 25 16 72 61 02 00 70 a2 25 17 02 ?? 25 18 72 fe 02 00 70 a2 25 19 03 a2 25 1a 72 5c 03 00 70 a2 28 14 00 00 0a 0b 06 07 28 07 00 00 06 26 2a } //1
		$a_03_1 = {72 81 05 00 70 0a 02 0b 16 0c 2b 1a 07 08 9a 0d 06 09 28 0a 00 00 ?? 72 ?? ?? ?? 70 28 13 00 00 0a 0a 08 17 58 0c 08 07 8e 69 32 e0 28 37 00 00 0a 13 04 12 04 28 38 00 00 0a 72 ?? ?? ?? 70 7e 03 00 00 04 28 13 00 00 0a 06 28 03 00 00 06 2a } //1
		$a_03_2 = {72 91 05 00 70 06 72 e7 ?? 00 70 28 13 00 00 0a 28 04 00 00 06 72 91 05 00 70 06 28 18 00 00 0a 28 05 00 00 06 [0-10] 6f 28 00 00 0a 2a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}