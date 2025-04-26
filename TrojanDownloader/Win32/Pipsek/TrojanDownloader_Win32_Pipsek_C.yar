
rule TrojanDownloader_Win32_Pipsek_C{
	meta:
		description = "TrojanDownloader:Win32/Pipsek.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {20 67 6f 74 6f 20 23 20 24 } //1  goto # $
		$a_01_1 = {63 3a 5c 74 65 20 2e 62 61 74 } //1 c:\te .bat
		$a_01_2 = {62 75 67 2e 37 65 60 43 59 43 53 25 3f } //1 bug.7e`CYCS%?
		$a_01_3 = {6b 65 79 62 64 5f 65 76 20 7a } //1 keybd_ev z
		$a_01_4 = {5c 6c 71 63 79 63 35 } //1 \lqcyc5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}