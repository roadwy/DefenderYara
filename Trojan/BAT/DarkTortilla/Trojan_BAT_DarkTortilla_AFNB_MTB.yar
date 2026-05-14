
rule Trojan_BAT_DarkTortilla_AFNB_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AFNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 14 fe 01 0d 09 2c 04 14 0a de 65 08 07 6f ?? 00 00 0a 00 08 07 6f ?? 00 00 0a 00 08 17 6f ?? 00 00 0a 00 08 18 6f ?? 00 00 0a 00 00 08 6f ?? 00 00 0a 13 04 00 11 04 02 16 02 8e 69 6f ?? 00 00 0a 0a de 2c } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}