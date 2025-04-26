
rule TrojanDownloader_Win32_Zemot_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Zemot.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 18 68 00 00 00 a0 6a ff ff 34 b0 57 ff 15 ?? ?? ?? ?? 46 3b 75 1c 72 e6 } //1
		$a_01_1 = {8b 78 04 0f b6 18 0f b7 ca 66 0f be 3c 0f 66 33 fb 66 33 fa bb ff 00 00 00 66 23 fb 42 66 89 3c 4e 66 3b 50 02 72 d9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}