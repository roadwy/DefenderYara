
rule Trojan_BAT_Snakelogger_PKUH_MTB{
	meta:
		description = "Trojan:BAT/Snakelogger.PKUH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 06 17 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 03 04 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0b de 13 } //8
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //2 CreateDecryptor
	condition:
		((#a_03_0  & 1)*8+(#a_01_1  & 1)*2) >=10
 
}