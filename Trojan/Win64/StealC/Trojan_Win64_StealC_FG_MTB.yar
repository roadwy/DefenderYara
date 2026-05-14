
rule Trojan_Win64_StealC_FG_MTB{
	meta:
		description = "Trojan:Win64/StealC.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 b8 9a 99 99 99 99 99 b9 3f 48 89 84 24 70 01 00 00 48 b8 9a 99 99 99 99 99 c9 3f 48 89 84 24 78 01 00 00 48 b8 33 33 33 33 33 33 d3 3f 48 89 84 24 80 01 00 00 48 b8 9a 99 99 99 99 99 d9 3f 48 89 84 24 88 01 00 00 48 b8 00 00 00 00 00 00 e0 3f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}