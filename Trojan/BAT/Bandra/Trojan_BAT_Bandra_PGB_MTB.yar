
rule Trojan_BAT_Bandra_PGB_MTB{
	meta:
		description = "Trojan:BAT/Bandra.PGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 12 00 28 ?? 00 00 0a 19 5b 18 5a 1f 14 58 28 ?? 00 00 0a 00 02 28 ?? 00 00 0a 6f ?? 00 00 0a 0a 12 00 28 ?? 00 00 0a 19 5b 18 5a 1f 14 59 28 ?? 00 00 0a 00 2a } //5
		$a_03_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 32 00 30 00 36 00 2e 00 31 00 38 00 39 00 2e 00 31 00 38 00 39 00 2e 00 35 00 37 00 2f 00 [0-0f] 00 7a 00 69 00 70 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}