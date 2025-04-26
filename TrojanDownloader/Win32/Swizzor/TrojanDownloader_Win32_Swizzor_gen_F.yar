
rule TrojanDownloader_Win32_Swizzor_gen_F{
	meta:
		description = "TrojanDownloader:Win32/Swizzor.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 28 33 ce 0f ac fe 08 81 e1 ff 00 00 00 33 34 cd ?? ?? ?? ?? c1 ef 08 33 3c cd ?? ?? ?? ?? 83 c0 01 3b c2 7c d8 } //1
		$a_03_1 = {c0 e1 04 99 f7 7e 04 8b 06 02 cb 8b 5f f4 8d 73 01 32 0c 02 8b 47 f8 88 4c 24 ?? b9 01 00 00 00 2b 4f fc 2b c6 0b c1 7d 0e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}