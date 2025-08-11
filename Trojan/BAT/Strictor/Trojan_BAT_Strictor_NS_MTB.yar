
rule Trojan_BAT_Strictor_NS_MTB{
	meta:
		description = "Trojan:BAT/Strictor.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 0a 2a 02 28 ?? 00 00 0a 7e ?? 00 00 04 7e ?? 00 00 04 7e ?? 00 00 04 6f ?? 01 00 0a 28 ?? 00 00 06 13 00 } //2
		$a_03_1 = {6b 00 00 04 7e ?? 00 00 04 7e ?? 00 00 04 6f ?? 01 00 0a 28 ?? 00 00 06 2a } //1
		$a_01_2 = {44 6f 63 5f 32 33 37 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Doc_237.Properties
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}