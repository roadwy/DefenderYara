
rule TrojanDownloader_Win32_Swizzor_gen_H{
	meta:
		description = "TrojanDownloader:Win32/Swizzor.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 73 01 32 0c 02 8b 47 f8 88 4c 24 17 b9 01 00 00 00 2b 4f fc 2b c6 0b c1 7d 0e } //1
		$a_03_1 = {0f be 04 19 33 c6 0f ac fe 08 25 ff 00 00 00 33 34 c5 ?? ?? ?? ?? c1 ef 08 33 3c c5 ?? ?? ?? ?? 41 3b ca 7c db } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}