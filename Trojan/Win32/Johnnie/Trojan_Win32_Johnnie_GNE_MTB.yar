
rule Trojan_Win32_Johnnie_GNE_MTB{
	meta:
		description = "Trojan:Win32/Johnnie.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {40 00 f1 4f 40 00 00 50 40 00 17 50 40 00 57 ?? 40 00 66 ?? 40 } //5
		$a_03_1 = {53 40 00 11 54 40 00 5c 54 ?? 00 e2 54 40 00 51 ?? 40 00 f4 55 40 00 04 56 40 00 06 } //5
		$a_80_2 = {64 65 69 6e 66 65 63 74 65 72 } //deinfecter  1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_80_2  & 1)*1) >=11
 
}