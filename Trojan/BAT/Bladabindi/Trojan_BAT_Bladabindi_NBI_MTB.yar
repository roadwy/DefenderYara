
rule Trojan_BAT_Bladabindi_NBI_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {1a 8d 29 00 00 01 0b 06 07 16 1a 6f ?? 00 00 0a 26 07 16 28 ?? 00 00 06 0c 06 16 73 ?? 00 00 0a 0d 08 8d ?? 00 00 01 13 04 16 28 ?? 00 00 06 39 ?? 00 00 00 26 20 ?? 00 00 00 38 ?? 00 00 00 09 11 04 16 08 28 ?? 00 00 06 26 38 ?? 00 00 00 } //5
		$a_01_1 = {53 45 45 44 43 52 41 43 4b 45 52 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 SEEDCRACKER.g.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}