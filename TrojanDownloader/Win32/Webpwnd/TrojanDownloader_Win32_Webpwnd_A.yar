
rule TrojanDownloader_Win32_Webpwnd_A{
	meta:
		description = "TrojanDownloader:Win32/Webpwnd.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {68 6f 6e 00 00 68 75 72 6c 6d 54 ff 16 } //1
		$a_02_1 = {33 c0 40 80 3c 03 00 75 f9 c7 04 03 5c ?? 2e 65 c7 44 03 04 78 65 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}