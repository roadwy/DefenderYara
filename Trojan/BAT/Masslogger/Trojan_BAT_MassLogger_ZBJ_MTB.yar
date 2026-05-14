
rule Trojan_BAT_MassLogger_ZBJ_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.ZBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 06 03 7d ?? 00 00 04 73 ?? 00 00 0a 25 16 02 7c ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 25 17 02 7c ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 25 18 02 } //6
		$a_03_1 = {25 2d 17 26 7e ?? 00 00 04 fe ?? 4e 00 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 02 03 04 6f ?? 00 00 0a 7d ?? 00 00 04 16 19 } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}