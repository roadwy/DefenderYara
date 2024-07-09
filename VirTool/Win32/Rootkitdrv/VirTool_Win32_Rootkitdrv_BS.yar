
rule VirTool_Win32_Rootkitdrv_BS{
	meta:
		description = "VirTool:Win32/Rootkitdrv.BS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 48 78 c7 40 34 00 ?? 01 00 e8 ?? ?? 00 00 33 c0 c2 08 00 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 c3 [0-06] 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb c3 } //1
		$a_01_1 = {81 ff 04 00 00 c0 75 16 81 c3 00 10 00 00 68 44 64 6b 20 53 6a 00 ff d5 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}