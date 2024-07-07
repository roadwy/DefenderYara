
rule Trojan_Win64_CobaltStrikeLoader_LKY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrikeLoader.LKY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 1f 03 d0 90 02 20 42 8a 8c 90 01 05 43 32 8c 90 01 05 48 8b 85 90 01 04 41 88 0c 90 01 01 44 03 cf 4c 03 90 01 01 44 3b 8d 90 01 02 00 00 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}