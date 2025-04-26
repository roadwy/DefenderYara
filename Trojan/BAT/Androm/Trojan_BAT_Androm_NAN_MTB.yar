
rule Trojan_BAT_Androm_NAN_MTB{
	meta:
		description = "Trojan:BAT/Androm.NAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 1a 11 1a 2c 30 11 04 72 ?? ?? 00 70 6f ?? ?? 00 0a 26 11 04 6f ?? ?? 00 0a 28 ?? ?? 00 0a 16 fe 01 13 1b 11 1b 2c 0d 11 04 6f ?? ?? 00 0a 28 ?? ?? 00 0a 26 00 72 ?? ?? 00 70 11 04 09 28 ?? ?? 00 0a 28 ?? ?? 00 0a 13 1c 11 1c 2c 24 02 7e ?? ?? 00 04 72 ?? ?? 00 70 6f ?? ?? 00 0a 09 6f ?? ?? 00 0a 28 ?? ?? 00 0a 28 ?? ?? 00 06 00 00 2b 18 00 08 16 9a 72 ?? ?? 00 70 11 04 } //5
		$a_01_1 = {42 6f 73 63 68 2d 45 43 55 2d 55 6c 74 69 6d 61 58 2d 54 6f 6f 6c } //1 Bosch-ECU-UltimaX-Tool
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}