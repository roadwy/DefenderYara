
rule Trojan_BAT_Remcos_ZKW_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ZKW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 06 11 04 6f ?? 01 00 0a 13 14 09 07 6f ?? 00 00 0a 59 13 06 11 06 19 fe 04 16 fe 01 13 0c 11 0c 2c 54 } //6
		$a_03_1 = {25 16 12 14 28 ?? 01 00 0a 9c 25 17 12 14 28 ?? 01 00 0a 9c 25 18 12 14 28 ?? 01 00 0a 9c 13 0d 11 09 20 d4 71 77 51 28 ?? 00 00 06 28 ?? 01 00 0a 2c 03 16 2b 01 16 13 0e 11 0e 2c 07 12 0d 28 ?? 00 00 06 07 11 0d 6f ?? 00 00 0a 2b 53 11 06 16 } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}