
rule Trojan_BAT_Masslogger_ZET_MTB{
	meta:
		description = "Trojan:BAT/Masslogger.ZET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 03 6f ?? 01 00 0a 0a 12 00 20 53 01 00 00 20 0c 01 00 00 28 ?? 00 00 06 9c 25 17 03 6f ?? 01 00 0a 0a 12 00 28 ?? 00 00 0a 9c 25 18 03 } //6
		$a_03_1 = {9c 2b 21 19 8d ?? 00 00 01 25 16 03 6f ?? 01 00 0a 9c 25 17 03 6f ?? 01 00 0a 9c 25 18 03 6f ?? 01 00 0a 9c 73 ?? 01 00 0a 2a } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}