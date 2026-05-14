
rule Trojan_Win64_XWorm_SLWV_MTB{
	meta:
		description = "Trojan:Win64/XWorm.SLWV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 8c 24 b8 00 00 00 89 4c 24 20 48 8b 8c 24 c0 00 00 00 4c 8b c9 44 8b c0 48 8b 54 24 60 48 8b 4c 24 58 ff 15 fd 50 01 00 48 8b 4c 24 58 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}