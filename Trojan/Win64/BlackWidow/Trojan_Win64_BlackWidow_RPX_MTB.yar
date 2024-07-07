
rule Trojan_Win64_BlackWidow_RPX_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 8c 24 c0 00 00 00 8b 89 dc 00 00 00 33 c8 8b c1 48 8b 8c 24 c0 00 00 00 89 81 dc 00 00 00 48 63 44 24 3c 48 8b 8c 24 c0 00 00 00 48 8b 89 b0 00 00 00 48 8b 94 24 c0 00 00 00 8b 52 5c 8b 04 81 33 c2 48 63 4c 24 3c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}