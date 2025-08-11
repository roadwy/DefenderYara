
rule Trojan_BAT_Taskun_ZWS_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZWS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 11 1e 11 1f 6f ?? 00 00 0a 13 21 11 08 6f ?? 00 00 0a 1f 64 fe 04 16 fe 01 13 33 11 33 2c 0a 00 11 08 } //6
		$a_01_1 = {15 5f 16 61 d2 13 26 11 24 16 60 d2 13 27 11 25 16 61 16 61 d2 13 28 11 1e 19 5a 13 29 11 1e 19 5a 17 58 } //5
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*5) >=11
 
}