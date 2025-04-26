
rule Backdoor_Linux_Mirai_CC_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CC!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {46 69 6e 64 69 6e 67 20 61 6e 64 20 6b 69 6c 6c 69 6e 67 20 70 72 6f 63 65 73 73 65 73 20 68 6f 6c 64 69 6e 67 20 70 6f 72 74 20 25 64 } //1 Finding and killing processes holding port %d
		$a_00_1 = {5b 64 62 67 20 2f 20 6b 69 6c 6c 65 72 5d } //1 [dbg / killer]
		$a_00_2 = {52 65 2d 73 63 61 6e 6e 69 6e 67 20 61 6c 6c 20 70 72 6f 63 65 73 73 65 73 } //1 Re-scanning all processes
		$a_02_3 = {5b 6b 69 6c 6c 65 72 20 2f 20 [0-10] 5d 20 4b 69 6c 6c 65 64 3a 20 25 73 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}