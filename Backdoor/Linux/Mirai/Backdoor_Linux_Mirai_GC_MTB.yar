
rule Backdoor_Linux_Mirai_GC_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.GC!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {21 30 60 01 21 58 80 01 21 60 e0 00 21 38 60 00 c0 1a 06 00 c2 2c 07 00 26 18 c3 00 26 28 e5 00 26 28 65 00 04 00 02 29 02 1a 03 00 21 20 60 00 ef ?? ?? ?? 26 18 65 00 0b ?? ?? ?? 26 18 85 00 00 00 43 a5 fe ff 08 25 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}