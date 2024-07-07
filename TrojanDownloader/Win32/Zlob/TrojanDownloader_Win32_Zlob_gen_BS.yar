
rule TrojanDownloader_Win32_Zlob_gen_BS{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!BS,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {88 04 2e 83 c6 01 83 c4 04 83 c3 04 3b f7 72 e8 90 09 08 00 53 e8 90 01 04 34 90 00 } //3
		$a_03_1 = {66 89 44 75 00 83 c6 01 83 c4 04 83 c3 04 3b f7 72 e4 90 09 0a 00 53 e8 90 01 04 66 35 90 00 } //3
		$a_11_2 = {6e 74 65 72 6e 65 74 47 65 74 43 6f 6e 6e 65 63 74 65 64 53 74 61 74 65 00 01 } //1 瑮牥敮䝴瑥潃湮捥整卤慴整Ā
		$a_68_3 = {74 70 3a 2f 2f 90 02 0f 2f 90 02 0f 2e 70 68 70 3f 90 00 } //5376
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_11_2  & 1)*1+(#a_68_3  & 1)*5376) >=7
 
}