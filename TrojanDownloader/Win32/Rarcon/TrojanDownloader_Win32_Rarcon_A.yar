
rule TrojanDownloader_Win32_Rarcon_A{
	meta:
		description = "TrojanDownloader:Win32/Rarcon.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 69 6e 72 61 72 5f 63 6f 6e 66 69 67 2e 74 6d 70 00 00 00 20 3e 20 6e 75 6c } //1
		$a_01_1 = {6e 39 6e 2e 6e 65 74 2f } //1 n9n.net/
		$a_01_2 = {3a 2f 2f 6b 70 2e 39 } //1 ://kp.9
		$a_01_3 = {75 61 6e 2e 69 63 6f } //1 uan.ico
		$a_01_4 = {73 74 61 72 74 2f 6d 69 6e 20 00 00 6f 6b 2e 62 61 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}