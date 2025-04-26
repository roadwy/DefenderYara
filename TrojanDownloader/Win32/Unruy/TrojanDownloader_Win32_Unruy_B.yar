
rule TrojanDownloader_Win32_Unruy_B{
	meta:
		description = "TrojanDownloader:Win32/Unruy.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {80 3b 58 75 36 80 7b ff 50 75 30 80 7b fe 55 75 2a 56 } //1
		$a_03_1 = {80 78 ff 50 75 ?? 80 78 fe 55 75 ?? 56 56 56 } //1
		$a_03_2 = {80 38 58 89 45 10 0f 85 ?? ?? ?? ?? 80 78 ff 50 75 7c 80 78 fe 55 75 76 } //1
		$a_01_3 = {73 70 6f 6f 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}