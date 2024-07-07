
rule Trojan_BAT_DiscoStealer_CJ_MTB{
	meta:
		description = "Trojan:BAT/DiscoStealer.CJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 09 df fc 16 2b 00 28 02 00 00 2b 28 ee 22 00 06 07 12 00 12 04 fe 15 02 00 00 1b 11 04 28 ef 22 00 06 16 28 f0 22 00 06 28 f1 22 00 06 25 28 f8 22 00 06 26 17 8d 39 00 00 01 25 16 1f 20 9d 28 f9 22 00 06 0c 08 8e 69 17 59 8d 2a 00 00 01 0d 20 1d db f8 55 13 0a 11 07 20 57 b6 f5 ff 5a 11 0a 61 38 } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}