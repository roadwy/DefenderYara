
rule VirTool_Win32_Injector_HH{
	meta:
		description = "VirTool:Win32/Injector.HH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {88 4d ff 8a 65 ff 8a 4d f7 32 e1 88 65 ff 8b 45 ec 03 45 e0 8a 4d ff 88 08 8b 55 e0 83 c2 01 89 55 e0 e9 } //1
		$a_01_1 = {c6 85 18 ff ff ff 56 c6 85 19 ff ff ff 69 c6 85 1a ff ff ff 72 c6 85 1b ff ff ff 74 c6 85 1c ff ff ff 75 c6 85 1d ff ff ff 61 c6 85 1e ff ff ff 6c c6 85 1f ff ff ff 41 c6 85 20 ff ff ff 6c c6 85 21 ff ff ff 6c c6 85 22 ff ff ff 6f c6 85 23 ff ff ff 63 } //1
		$a_01_2 = {51 8b 55 f8 52 ff 55 fc 89 85 98 fe ff ff 8d 45 98 50 8b 4d f8 51 ff 55 fc 89 85 c8 fe ff ff } //1
		$a_01_3 = {eb dd 8b 8d a8 fe ff ff 8b 55 f4 03 51 28 89 55 cc ff 55 cc 6a 00 ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}