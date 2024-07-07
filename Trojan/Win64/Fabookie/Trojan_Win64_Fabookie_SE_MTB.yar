
rule Trojan_Win64_Fabookie_SE_MTB{
	meta:
		description = "Trojan:Win64/Fabookie.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 b9 40 00 00 00 48 8d 4d 10 41 b8 e8 03 00 00 48 89 4c 24 20 48 8b d3 48 83 c9 ff ff d0 48 8b c3 b9 3c 03 00 00 80 00 08 48 ff c0 48 83 e9 01 75 f4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}