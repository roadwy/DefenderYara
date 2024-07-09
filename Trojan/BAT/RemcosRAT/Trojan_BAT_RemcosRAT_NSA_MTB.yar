
rule Trojan_BAT_RemcosRAT_NSA_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.NSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {38 58 00 00 00 11 01 28 ?? 00 00 0a 13 02 38 ?? 00 00 00 11 02 13 03 38 ?? 00 00 00 11 02 16 11 02 8e 69 28 11 00 00 0a } //5
		$a_01_1 = {4e 00 65 00 77 00 20 00 51 00 75 00 6f 00 74 00 65 00 20 00 4f 00 72 00 64 00 65 00 72 00 } //1 New Quote Order
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}