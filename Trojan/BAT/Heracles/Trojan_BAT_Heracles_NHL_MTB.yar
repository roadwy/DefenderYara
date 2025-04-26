
rule Trojan_BAT_Heracles_NHL_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {72 53 10 00 70 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 17 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a } //5
		$a_01_1 = {50 72 6f 63 65 73 73 57 69 6e 64 6f 77 53 74 79 6c 65 } //1 ProcessWindowStyle
		$a_01_2 = {45 00 6e 00 64 00 65 00 72 00 49 00 63 00 65 00 32 00 } //1 EnderIce2
		$a_01_3 = {63 00 6f 00 6d 00 70 00 75 00 74 00 61 00 72 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 computar.Properties.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}