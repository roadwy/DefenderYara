
rule HackTool_BAT_FakeRansom_RDA_MTB{
	meta:
		description = "HackTool:BAT/FakeRansom.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 64 65 32 65 37 31 66 2d 36 32 39 61 2d 34 65 61 39 2d 61 37 39 39 2d 30 66 36 30 33 36 30 39 66 65 32 38 } //1 dde2e71f-629a-4ea9-a799-0f603609fe28
		$a_01_1 = {46 61 6b 65 52 61 6e 73 6f 6d 77 61 72 65 } //1 FakeRansomware
		$a_01_2 = {6b 74 68 78 62 61 69 } //1 kthxbai
		$a_01_3 = {42 6c 61 63 6b 57 69 6e 64 6f 77 } //1 BlackWindow
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}