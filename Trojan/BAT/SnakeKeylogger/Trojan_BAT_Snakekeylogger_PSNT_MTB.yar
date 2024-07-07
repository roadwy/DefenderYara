
rule Trojan_BAT_Snakekeylogger_PSNT_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.PSNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 40 0a 00 70 06 72 4c 0a 00 70 6f 90 01 03 0a 72 56 0a 00 70 72 5a 0a 00 70 6f 90 01 03 0a 28 90 01 03 0a 0b 73 90 01 03 0a 0c 16 0d 2b 20 00 07 09 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 13 05 08 11 05 6f 90 01 03 0a 00 09 18 58 0d 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}