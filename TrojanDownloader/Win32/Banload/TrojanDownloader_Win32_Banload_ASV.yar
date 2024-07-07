
rule TrojanDownloader_Win32_Banload_ASV{
	meta:
		description = "TrojanDownloader:Win32/Banload.ASV,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 ff 5b } //1
		$a_01_1 = {0f b6 44 30 ff 33 c3 89 45 } //1
		$a_01_2 = {8b 18 ff 53 10 83 7d e8 00 75 d0 33 c0 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10) >=12
 
}