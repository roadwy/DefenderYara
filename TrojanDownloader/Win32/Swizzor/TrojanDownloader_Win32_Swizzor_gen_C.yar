
rule TrojanDownloader_Win32_Swizzor_gen_C{
	meta:
		description = "TrojanDownloader:Win32/Swizzor.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {2e 00 00 00 [0-05] 0f 00 00 00 [0-20] b8 2e 00 00 00 [0-0a] b9 0f 00 00 00 } //1
		$a_03_1 = {8b 4a 3c 01 ?? 8b 51 7c 8b ?? 78 } //1
		$a_03_2 = {7f 02 00 00 0f 8d [0-10] 81 ?? 7f 00 00 00 0f 8f 90 09 02 00 } //1
		$a_03_3 = {85 c0 0f 84 [0-1a] c1 ?? 05 c1 2d ?? ?? ?? 00 1b 0b ?? ?? ?? ?? 00 (83 e8 41|81 e8 41 00 00 00) 01 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*10) >=12
 
}