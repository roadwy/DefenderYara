
rule Trojan_BAT_DarkTortilla_ABWA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ABWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 74 ?? 00 00 01 14 fe 03 13 07 11 07 2c 05 1a 13 11 2b a5 17 2b f9 11 04 74 ?? 00 00 01 08 75 ?? 00 00 1b 6f ?? 00 00 0a 11 04 74 ?? 00 00 01 08 75 ?? 00 00 1b 6f ?? 00 00 0a 16 13 11 38 ?? ff ff ff 11 04 75 ?? 00 00 01 6f ?? 00 00 0a 13 08 73 ?? 00 00 0a 13 05 11 05 74 ?? 00 00 01 11 08 74 ?? 00 00 01 17 73 ?? 00 00 0a 13 06 1c 13 11 38 ?? ff ff ff 11 06 14 16 } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}