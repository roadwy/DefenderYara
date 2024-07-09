
rule TrojanDownloader_Win32_Adload_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Adload.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {2f 2f 77 77 77 2e 4d 6f 4b 65 41 44 2e 63 } //1 //www.MoKeAD.c
		$a_00_1 = {2f 2f 77 31 2e 4d 6f 4b 65 41 44 2e 63 } //1 //w1.MoKeAD.c
		$a_00_2 = {2f 2f 77 32 2e 4d 6f 4b 65 41 44 2e 63 } //1 //w2.MoKeAD.c
		$a_00_3 = {2f 2f 77 33 2e 4d 6f 4b 65 41 44 2e 63 } //1 //w3.MoKeAD.c
		$a_00_4 = {2f 2f 77 34 2e 4d 6f 4b 65 41 44 2e 63 } //1 //w4.MoKeAD.c
		$a_00_5 = {2f 2f 77 35 2e 4d 6f 4b 65 41 44 2e 63 } //1 //w5.MoKeAD.c
		$a_00_6 = {53 65 72 53 65 74 75 70 2e 65 78 65 } //1 SerSetup.exe
		$a_02_7 = {43 68 65 63 6b 55 70 64 61 74 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 62 61 6b ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_02_7  & 1)*1) >=8
 
}