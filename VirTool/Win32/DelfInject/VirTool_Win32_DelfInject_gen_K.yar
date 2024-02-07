
rule VirTool_Win32_DelfInject_gen_K{
	meta:
		description = "VirTool:Win32/DelfInject.gen!K,SIGNATURE_TYPE_PEHSTR_EXT,20 00 1f 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 } //0a 00  FindResourceA
		$a_00_1 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //0a 00  LoadResource
		$a_01_2 = {52 74 6c 44 65 63 6f 6d 70 72 65 73 73 42 75 66 66 65 72 } //02 00  RtlDecompressBuffer
		$a_02_3 = {8b 45 fc 8b 55 f4 8a 44 10 ff 88 45 f3 8d 45 e8 8a 55 f3 80 ea 90 01 01 e8 90 01 04 8b 55 e8 8b 45 f8 e8 90 01 04 8b 45 f8 ff 45 f4 ff 4d ec 75 cf 90 00 } //02 00 
		$a_03_4 = {44 38 ff 88 45 fb 8d 45 f4 8a 55 fb 80 ea 90 01 01 e8 90 01 04 8b 55 f4 8b c6 e8 90 01 04 47 4b 75 da 90 09 04 00 8b 45 fc 90 03 01 01 8a 8b 90 00 } //01 00 
		$a_00_5 = {8b c3 99 03 45 e0 13 55 e4 33 04 24 33 54 24 04 83 c4 08 5a 88 02 43 46 4f 75 } //01 00 
		$a_00_6 = {53 54 52 00 ff ff ff ff 01 00 00 00 5c 00 00 00 ff ff ff ff 04 00 00 00 2e 65 78 65 } //01 00 
		$a_03_7 = {6a 40 68 00 30 00 00 8b 45 90 01 01 50 8b 45 90 01 01 8b 40 34 50 8b 90 03 06 04 85 90 01 02 ff ff 45 90 01 01 50 90 03 01 01 ff e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}