
rule Trojan_BAT_Snakekeylogger_SCXF_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.SCXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 08 17 73 ?? 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 13 05 dd 2f 00 00 00 11 04 } //2
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}