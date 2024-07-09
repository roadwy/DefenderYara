
rule Trojan_BAT_RemcosRAT_NR_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {58 13 03 20 0e 00 00 00 fe ?? ?? 00 38 ?? ?? ?? ff 16 6a 13 00 20 ?? ?? ?? 00 fe ?? ?? 00 38 ?? ?? ?? ff } //5
		$a_01_1 = {42 6e 6e 69 79 64 74 64 } //1 Bnniydtd
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_RemcosRAT_NR_MTB_2{
	meta:
		description = "Trojan:BAT/RemcosRAT.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {17 2d 06 d0 11 00 00 06 26 72 ?? 00 00 70 0a 06 28 ?? 00 00 0a 25 26 0b 28 ?? 00 00 0a 25 26 07 16 07 8e 69 6f ?? 00 00 0a 0a 28 ?? 00 00 0a 25 26 06 6f ?? 00 00 0a } //5
		$a_01_1 = {42 48 48 48 47 36 36 } //1 BHHHG66
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}