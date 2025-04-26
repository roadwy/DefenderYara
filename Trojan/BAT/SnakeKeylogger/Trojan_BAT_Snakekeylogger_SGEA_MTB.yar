
rule Trojan_BAT_Snakekeylogger_SGEA_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.SGEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 11 } //3
		$a_03_1 = {09 11 06 58 1f 64 5d 13 07 09 11 06 5a 1f 64 5d 13 08 09 11 06 61 1f 64 5d 13 09 02 09 11 06 6f ?? 00 00 0a 13 0a } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1) >=4
 
}