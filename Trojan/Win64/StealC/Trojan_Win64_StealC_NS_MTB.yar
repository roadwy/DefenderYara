
rule Trojan_Win64_StealC_NS_MTB{
	meta:
		description = "Trojan:Win64/StealC.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {7d 20 48 63 44 24 ?? 48 8b 4c 24 58 8b 04 01 03 44 24 ?? 48 63 4c 24 ?? 48 8b 54 24 30 89 04 } //3
		$a_03_1 = {8b 44 24 20 83 c0 ?? 89 44 24 20 81 7c 24 20 00 60 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}