
rule HackTool_BAT_Windissec_NL_MTB{
	meta:
		description = "HackTool:BAT/Windissec.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {7e 82 00 00 04 03 07 6a 58 e0 47 06 61 20 ff ?? ?? ?? 5f 95 06 1e 64 61 0a 07 17 58 0b 07 6a 04 6e 3f da ff ff ff } //5
		$a_80_1 = {2f 63 20 73 63 20 73 74 6f 70 20 76 67 63 } ///c sc stop vgc  1
		$a_80_2 = {44 69 73 61 62 6c 65 20 79 6f 75 72 20 41 6e 74 69 2d 56 69 72 75 73 } //Disable your Anti-Virus  1
		$a_80_3 = {73 63 20 64 65 6c 65 74 65 20 66 61 63 65 69 74 } //sc delete faceit  1
	condition:
		((#a_03_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=8
 
}