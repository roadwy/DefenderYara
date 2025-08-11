
rule Trojan_BAT_Vipkeylogger_AVK_MTB{
	meta:
		description = "Trojan:BAT/Vipkeylogger.AVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 40 2b 44 00 11 3e 11 40 19 5f 91 13 41 11 41 16 60 11 41 fe 01 13 42 11 42 13 43 11 43 2c 21 00 03 11 41 6f ?? 00 00 0a 00 11 1e 11 3f 5a 11 40 58 13 44 11 07 11 44 11 41 6f ?? 00 00 0a 00 00 00 11 40 17 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}