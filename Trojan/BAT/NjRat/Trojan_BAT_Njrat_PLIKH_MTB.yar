
rule Trojan_BAT_Njrat_PLIKH_MTB{
	meta:
		description = "Trojan:BAT/Njrat.PLIKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 00 06 08 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 03 16 03 8e 69 6f ?? 00 00 0a 13 04 11 04 13 05 11 05 74 ?? 00 00 1b 13 06 2b 00 11 06 2a } //10
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}