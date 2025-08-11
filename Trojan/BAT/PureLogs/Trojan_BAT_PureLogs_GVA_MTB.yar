
rule Trojan_BAT_PureLogs_GVA_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.GVA!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {3a 00 2f 00 2f 00 31 00 34 00 34 00 2e 00 31 00 37 00 32 00 2e 00 31 00 32 00 32 00 2e 00 36 00 39 00 } //2 ://144.172.122.69
		$a_01_1 = {65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 20 00 6b 00 65 00 79 00 } //1 encryption key
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}