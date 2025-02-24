
rule Trojan_Win64_BlackWidow_ZZP_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.ZZP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 f7 f0 c4 43 2d 0f d2 08 45 8a 14 11 c4 43 1d 0f e4 ?? c4 43 1d 46 e0 13 c4 e3 5d 0f e4 04 c4 43 1d 0f e4 0c c4 43 2d 0f d2 08 c4 43 0d 0f f6 04 c5 cd 72 d6 19 48 83 c7 02 0f f5 c2 44 30 54 0f ?? c4 43 1d 0f e4 0c 48 83 ef 02 c4 e3 5d 0f e4 04 48 ff c1 c4 43 1d 46 e0 13 48 89 c8 0f 6a cc 48 81 f9 d3 35 01 00 0f 86 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}