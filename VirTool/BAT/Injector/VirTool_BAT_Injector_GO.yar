
rule VirTool_BAT_Injector_GO{
	meta:
		description = "VirTool:BAT/Injector.GO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 72 6f 69 61 00 } //1 牴楯a
		$a_01_1 = {66 6f 73 67 61 00 } //1 潦杳a
		$a_80_2 = {2e 73 61 6f 6a 6f 61 6f 2e 50 72 6f 70 65 72 74 69 65 73 00 } //.saojoao.Properties  1
		$a_00_3 = {70 00 65 00 64 00 72 00 6f 00 6b 00 71 00 73 00 75 00 } //1 pedrokqsu
		$a_00_4 = {34 61 37 64 62 36 62 31 2d 37 62 38 33 2d 34 36 64 63 2d 61 32 66 32 2d 65 65 33 34 61 34 37 30 33 35 33 30 } //1 4a7db6b1-7b83-46dc-a2f2-ee34a4703530
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}