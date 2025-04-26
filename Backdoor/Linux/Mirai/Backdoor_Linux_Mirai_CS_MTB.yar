
rule Backdoor_Linux_Mirai_CS_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CS!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {00 b4 80 00 00 0d c0 a0 e1 10 d8 2d e9 04 b0 4c e2 24 d0 4d e2 18 00 0b e5 1c 10 0b e5 18 30 1b e5 00 30 d3 e5 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}