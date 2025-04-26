
rule VirTool_BAT_Injector_IM{
	meta:
		description = "VirTool:BAT/Injector.IM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 53 00 4f 62 6a 65 63 74 00 42 00 43 00 54 00 } //1 卆伀橢捥tBCT
		$a_01_1 = {42 61 73 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00 46 6f 72 6d 31 00 } //1
		$a_00_2 = {2e 00 78 00 7b 00 30 00 7d 00 } //1 .x{0}
		$a_00_3 = {41 00 64 00 76 00 65 00 72 00 73 00 75 00 73 00 20 00 73 00 6f 00 6c 00 65 00 6d 00 20 00 6e 00 65 00 20 00 6c 00 6f 00 71 00 75 00 69 00 74 00 6f 00 72 00 21 00 } //1 Adversus solem ne loquitor!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}