
rule TrojanDownloader_Win32_Kucf_A{
	meta:
		description = "TrojanDownloader:Win32/Kucf.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 75 63 6b 79 6f 75 61 6e 74 69 76 69 72 75 73 00 } //1
		$a_01_1 = {6c 6f 6c 00 } //1 潬l
		$a_01_2 = {63 6d 64 20 2f 63 20 63 6f 70 79 20 } //1 cmd /c copy 
		$a_01_3 = {6c 6f 67 2e 68 74 6d 6c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}