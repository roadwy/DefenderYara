
rule TrojanDownloader_Win32_Harnig_gen_F{
	meta:
		description = "TrojanDownloader:Win32/Harnig.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 08 00 09 00 00 "
		
	strings :
		$a_01_0 = {5c 74 73 61 73 78 63 2e 65 78 65 } //1 \tsasxc.exe
		$a_01_1 = {5c 69 79 62 6b 65 67 65 2e 65 78 65 } //1 \iybkege.exe
		$a_01_2 = {5c 78 6a 6b 6a 74 65 61 2e 65 78 65 } //1 \xjkjtea.exe
		$a_01_3 = {5c 64 6d 66 78 79 71 74 2e 65 78 65 } //1 \dmfxyqt.exe
		$a_01_4 = {5c 6f 63 71 68 62 2e 65 78 65 } //1 \ocqhb.exe
		$a_01_5 = {5c 65 77 66 71 62 2e 65 78 65 } //1 \ewfqb.exe
		$a_01_6 = {5c 61 76 69 72 78 2e 65 78 65 } //1 \avirx.exe
		$a_01_7 = {5c 6f 64 6d 63 73 6b 2e 65 78 65 } //1 \odmcsk.exe
		$a_02_8 = {00 56 57 8b 7c 24 ?? 57 33 f6 ff d3 85 c0 7e 0c 80 04 3e d1 57 46 ff d3 3b f0 7c f4 5f 5e 5b c2 04 00 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_02_8  & 1)*5) >=8
 
}