
rule Trojan_BAT_ZgRAT_NZ_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 11 02 6f ?? 00 00 0a 28 ?? 00 00 2b 6f ?? 00 00 0a 13 0d 20 17 00 00 00 38 70 fd ff ff 11 0a 18 5d 3a ?? ff ff ff 20 ?? 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 ?? fd ff ff 26 } //4
		$a_01_1 = {4f 70 65 6e 50 6f 70 2e 50 72 6f 70 65 72 74 69 65 73 } //1 OpenPop.Properties
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}