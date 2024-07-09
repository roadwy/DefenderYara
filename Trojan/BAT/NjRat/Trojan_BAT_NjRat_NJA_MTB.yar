
rule Trojan_BAT_NjRat_NJA_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 e0 07 11 0e 11 0f 19 58 58 e0 91 1f 18 62 07 11 0e 11 0f 18 58 58 e0 91 1f 10 62 60 07 } //5
		$a_01_1 = {6d 69 6e 69 20 63 61 6c 63 75 6c 61 74 6f 72 } //1 mini calculator
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_NjRat_NJA_MTB_2{
	meta:
		description = "Trojan:BAT/NjRat.NJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {38 0f 00 00 00 26 20 ?? ?? ?? 00 fe ?? ?? 00 38 ?? ?? ?? ff 08 14 72 ?? ?? ?? 70 18 8d ?? ?? ?? 01 14 14 14 17 28 ?? ?? ?? 0a 26 dd ?? ?? ?? 00 } //5
		$a_01_1 = {57 69 6e 64 6f 77 73 41 70 70 31 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 WindowsApp1.g.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}