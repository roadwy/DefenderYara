
rule Trojan_Win64_BlackWidow_RPZ_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 05 00 30 00 00 48 8b 8c 24 f0 00 00 00 48 89 81 b0 00 00 00 8b 44 24 44 35 1b 0f 00 00 89 44 24 44 8b 44 24 50 35 ca 05 00 00 89 84 24 84 00 00 00 8b 44 24 54 2d 29 05 00 00 89 84 24 80 00 00 00 8b 44 24 54 05 b1 00 00 00 89 44 24 7c 8b 44 24 4c 35 74 0a 00 00 89 44 24 78 8b 44 24 4c 05 6f 05 00 00 89 44 24 74 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}