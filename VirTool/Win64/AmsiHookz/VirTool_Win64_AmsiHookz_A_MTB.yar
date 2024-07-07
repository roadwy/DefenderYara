
rule VirTool_Win64_AmsiHookz_A_MTB{
	meta:
		description = "VirTool:Win64/AmsiHookz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {41 6d 73 69 53 63 61 6e 42 75 66 66 65 72 } //1 AmsiScanBuffer
		$a_00_1 = {4c 89 4c 24 20 44 89 44 24 18 48 89 54 24 10 48 89 4c 24 08 48 83 ec 38 48 8d } //1
		$a_02_2 = {48 8b 44 24 68 48 89 44 24 28 48 8b 44 24 60 48 89 44 24 20 4c 8b 4c 24 58 44 8b 44 24 50 48 8d 90 01 05 48 8b 4c 24 40 ff 15 90 01 04 48 83 c4 38 c3 90 00 } //1
		$a_02_3 = {83 7c 24 48 01 75 90 01 01 ff 15 90 01 04 b9 01 00 00 00 90 00 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}