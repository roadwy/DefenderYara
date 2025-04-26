
rule Trojan_BAT_DarkTortilla_PSAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.PSAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 73 71 01 00 0a 0d 14 13 04 00 09 08 17 28 ?? 01 00 06 13 04 11 04 02 7b ?? 01 00 04 16 02 7b ?? 01 00 04 8e 69 6f ?? 01 00 0a 00 11 04 6f ?? 01 00 0a 00 09 13 05 11 05 0a de 28 00 11 04 14 fe 03 13 06 11 06 2c 08 11 04 6f } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}