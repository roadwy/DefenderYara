
rule Backdoor_Linux_Mirai_CQ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CQ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {64 64 69 72 00 63 6f 6e 6e 65 63 74 00 5f 5f 66 64 65 6c 74 5f 63 68 6b 00 63 6c 6f 73 65 64 69 72 00 73 69 67 6e } //1 摤物挀湯敮瑣开晟敤瑬损歨挀潬敳楤r楳湧
		$a_00_1 = {c0 9f e5 04 c0 2d e5 0c 00 9f e5 0c 30 9f e5 d3 43 00 ea fd 3d 00 eb 28 dc 01 00 f0 02 01 00 d4 80 00 00 f0 4f 2d e9 51 dc 4d e2 74 d0 4d e2 02 40 a0 e1 03 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}