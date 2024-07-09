
rule BrowserModifier_Win32_Procesemes_C{
	meta:
		description = "BrowserModifier:Win32/Procesemes.C,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 00 72 00 6f 00 6e 00 67 00 20 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 63 00 6f 00 64 00 65 00 } //10 Wrong security code
		$a_00_1 = {25 25 6e 61 6d 65 5f 66 69 6c 65 5f 30 32 25 25 } //10 %%name_file_02%%
		$a_02_2 = {50 00 4e 00 47 00 00 00 [0-0f] 2e 00 64 00 6c 00 6c } //10
		$a_00_3 = {6f 00 6e 00 6c 00 79 00 78 00 70 00 6f 00 72 00 6e 00 76 00 69 00 64 00 65 00 6f 00 2e 00 63 00 6f 00 6d 00 } //1 onlyxpornvideo.com
		$a_00_4 = {62 00 65 00 73 00 74 00 78 00 78 00 78 00 76 00 69 00 64 00 65 00 6f 00 34 00 66 00 72 00 65 00 65 00 2e 00 63 00 6f 00 6d 00 } //1 bestxxxvideo4free.com
		$a_00_5 = {6f 00 6e 00 6c 00 69 00 6e 00 65 00 73 00 65 00 78 00 7a 00 6f 00 6e 00 65 00 2e 00 63 00 6f 00 6d 00 } //1 onlinesexzone.com
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*10+(#a_02_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=31
 
}