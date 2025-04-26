
rule Trojan_BAT_Crysan_EAQ_MTB{
	meta:
		description = "Trojan:BAT/Crysan.EAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 00 18 5b 11 02 11 00 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 38 ?? 00 00 00 11 03 18 5b 8d ?? 00 00 01 13 04 20 01 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? ff ff ff 26 20 01 00 00 00 38 ?? ff ff ff 11 04 13 06 38 ?? 00 00 00 11 00 18 58 13 00 38 } //3
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 38 00 34 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 WindowsFormsApp84.Properties.Resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}