
rule TrojanDownloader_Win32_Swizzor_gen_E{
	meta:
		description = "TrojanDownloader:Win32/Swizzor.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 d8 8b c6 d1 e8 03 44 24 ?? 8b 0d ?? ?? ?? ?? 99 f7 3d ?? ?? ?? ?? 83 c6 02 83 c4 08 83 c7 01 32 1c 0a 3b 74 24 ?? 88 5f ff 7c ba } //1
		$a_01_1 = {3b c6 75 09 b8 a1 7a 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}