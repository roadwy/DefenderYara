
rule Trojan_BAT_Keylogger_DB_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0a 7e 59 00 00 04 07 06 6f 92 00 00 0a 28 93 00 00 0a 0d 28 91 00 00 0a 09 16 09 8e 69 6f 92 00 00 0a 28 94 00 00 0a 13 04 7e 5c 00 00 04 2c 08 02 11 04 28 bc 00 00 06 11 04 13 05 de 06 } //1
		$a_03_1 = {2d da 16 2d d7 2a 0a 2b ce 03 2b d5 06 2b d4 07 2b d4 6f ?? ?? ?? 0a 2b d4 02 2b d6 06 2b d5 06 2b d5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}