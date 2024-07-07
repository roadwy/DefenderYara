
rule VirTool_BAT_DaskStealLoadRes_MTB{
	meta:
		description = "VirTool:BAT/DaskStealLoadRes!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 75 74 74 65 72 46 6c 79 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 ButterFly.g.resources
		$a_01_1 = {5a 6f 72 6b 47 61 6d 65 2e 50 72 6f 70 65 72 74 69 65 73 } //1 ZorkGame.Properties
		$a_01_2 = {74 45 58 74 53 6f 66 74 77 61 72 65 } //1 tEXtSoftware
		$a_01_3 = {53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 2e 42 69 74 6d 61 70 } //1 System.Drawing.Bitmap
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}