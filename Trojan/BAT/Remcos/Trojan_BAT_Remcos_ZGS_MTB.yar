
rule Trojan_BAT_Remcos_ZGS_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ZGS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 10 11 13 17 58 13 13 11 13 1f 0a fe 04 13 12 00 02 11 2c 11 30 6f ?? 01 00 0a 13 31 11 17 12 31 28 ?? 01 00 0a 58 13 17 11 18 12 31 28 ?? 01 00 0a 58 13 18 11 19 12 31 28 ?? 01 00 0a 58 13 19 12 31 } //6
		$a_03_1 = {11 0e 12 31 28 ?? 01 00 0a 61 d2 13 0e 11 0e 12 31 28 ?? 01 00 0a 61 d2 13 0e 11 0e 12 31 28 ?? 01 00 0a 61 d2 13 0e 11 1a 1f 64 5d 16 fe 01 } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}