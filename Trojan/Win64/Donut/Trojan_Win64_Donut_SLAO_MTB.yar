
rule Trojan_Win64_Donut_SLAO_MTB{
	meta:
		description = "Trojan:Win64/Donut.SLAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 4a f7 ff 66 c7 42 ff 00 0a 44 89 72 03 66 c7 42 2f 00 0a c6 42 31 0a 44 89 72 47 44 88 72 43 48 8b 05 21 c9 14 00 48 83 c2 58 48 8d 4a f7 48 05 00 0b 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}