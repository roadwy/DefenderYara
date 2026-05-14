
rule HackTool_Linux_PipelineCmdLineTest_A{
	meta:
		description = "HackTool:Linux/PipelineCmdLineTest.A,SIGNATURE_TYPE_CMDHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_00_0 = {77 00 64 00 6c 00 69 00 6e 00 75 00 78 00 5f 00 70 00 69 00 70 00 65 00 6c 00 69 00 6e 00 65 00 5f 00 73 00 74 00 61 00 67 00 65 00 31 00 5f 00 65 00 32 00 65 00 } //10 wdlinux_pipeline_stage1_e2e
		$a_00_1 = {77 00 64 00 6c 00 69 00 6e 00 75 00 78 00 5f 00 70 00 69 00 70 00 65 00 6c 00 69 00 6e 00 65 00 5f 00 73 00 74 00 61 00 67 00 65 00 32 00 5f 00 65 00 32 00 65 00 } //10 wdlinux_pipeline_stage2_e2e
		$a_00_2 = {77 00 64 00 6c 00 69 00 6e 00 75 00 78 00 5f 00 70 00 69 00 70 00 65 00 6c 00 69 00 6e 00 65 00 5f 00 73 00 74 00 61 00 67 00 65 00 33 00 5f 00 65 00 32 00 65 00 } //10 wdlinux_pipeline_stage3_e2e
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=30
 
}