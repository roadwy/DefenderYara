
rule Trojan_BAT_OrcusRAT_NR_MTB{
	meta:
		description = "Trojan:BAT/OrcusRAT.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 05 9a 0c 08 6f ?? 00 00 0a 2c 42 08 6f ?? 00 00 0a 72 ?? 00 00 70 03 28 38 00 00 0a } //3
		$a_03_1 = {6f 39 00 00 0a 2c 2a 08 28 ?? 00 00 0a 28 ?? 00 00 0a 0d 08 04 20 00 01 00 00 14 09 28 ?? 00 00 0a 05 6f ?? 00 00 0a 28 ?? 00 00 0a 13 04 11 04 2a 11 05 17 d6 13 05 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}