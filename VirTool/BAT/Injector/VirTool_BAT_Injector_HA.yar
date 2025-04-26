
rule VirTool_BAT_Injector_HA{
	meta:
		description = "VirTool:BAT/Injector.HA,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {2e 00 50 00 45 00 } //1 .PE
		$a_00_1 = {73 00 65 00 63 00 74 00 6f 00 72 00 } //1 sector
		$a_00_2 = {73 00 61 00 6f 00 6a 00 6f 00 61 00 6f 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 } //1 saojoao.Properties.
		$a_00_3 = {73 00 61 00 6f 00 6a 00 6f 00 73 00 65 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 } //1 saojose.Properties.
		$a_01_4 = {11 05 91 08 61 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}