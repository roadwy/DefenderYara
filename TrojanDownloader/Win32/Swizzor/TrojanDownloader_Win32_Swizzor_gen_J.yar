
rule TrojanDownloader_Win32_Swizzor_gen_J{
	meta:
		description = "TrojanDownloader:Win32/Swizzor.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b c5 99 2b c2 d1 f8 03 c7 99 f7 7e 04 8b 06 c0 e1 04 02 cb 32 0c 02 } //1
		$a_03_1 = {35 00 00 00 d8 89 0c fd ?? ?? ?? ?? 89 04 fd ?? ?? ?? ?? 47 81 ff ff 00 00 00 0f 8e 1d ff ff ff } //1
		$a_03_2 = {8b 8e a4 00 00 00 53 68 58 1b 00 00 51 32 db ff 15 ?? ?? ?? ?? 85 c0 75 33 39 46 38 74 21 8b 7c 24 10 8b 96 a8 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}