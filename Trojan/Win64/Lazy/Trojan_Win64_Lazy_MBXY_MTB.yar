
rule Trojan_Win64_Lazy_MBXY_MTB{
	meta:
		description = "Trojan:Win64/Lazy.MBXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 c1 e9 1e 33 c8 69 c1 65 89 07 6c 03 c2 89 84 94 84 0c 00 00 48 ff c2 48 81 fa 70 02 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}