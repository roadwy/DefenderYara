
rule Backdoor_Linux_Mirai_JY_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JY!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {75 28 8b 44 24 38 2b 46 f8 83 f8 1e 0f 87 18 04 00 00 8b 46 f0 89 c2 83 e0 1f c1 ea 05 0f ab 84 94 78 50 00 00 e9 f0 03 00 00 3c 04 } //1
		$a_00_1 = {e8 e9 f6 ff ff 0f b7 c0 89 44 24 04 8b 44 24 04 66 c1 c8 08 66 3d ff 03 76 e6 } //1
		$a_00_2 = {6c 6f 73 74 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 77 69 74 68 20 43 4e 43 } //1 lost connection with CNC
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}