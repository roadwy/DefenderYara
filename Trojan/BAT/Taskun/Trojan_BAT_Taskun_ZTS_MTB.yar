
rule Trojan_BAT_Taskun_ZTS_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 46 11 47 6f ?? 00 00 0a 13 48 00 2b 09 00 28 ?? 00 00 0a 13 48 00 12 48 28 ?? 00 00 0a 20 c8 00 00 00 fe 02 13 56 11 56 2c 09 72 79 06 00 70 13 23 2b 41 12 48 28 ?? 00 00 0a 20 c8 00 00 00 fe 02 13 57 11 57 2c 09 72 9d 06 00 70 13 23 2b 24 12 48 28 ?? 00 00 0a 20 c8 00 00 00 fe 02 13 58 11 58 2c 09 72 c5 06 00 70 13 23 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}