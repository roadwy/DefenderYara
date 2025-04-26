
rule TrojanDownloader_Win32_Dumcus_A{
	meta:
		description = "TrojanDownloader:Win32/Dumcus.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 f8 70 0f 85 81 00 00 00 0f be 46 01 50 e8 ?? ?? ?? ?? 59 83 f8 61 75 71 0f be 46 02 50 e8 ?? ?? ?? ?? 59 83 f8 73 } //1
		$a_01_1 = {f7 d8 1b c0 f7 d8 40 40 03 cf 00 01 47 eb d9 } //1
		$a_01_2 = {73 76 63 68 6f 2e 65 78 65 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}