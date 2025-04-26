
rule TrojanDownloader_Win32_Tricom_A_bit{
	meta:
		description = "TrojanDownloader:Win32/Tricom.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6c 00 61 00 70 00 61 00 70 00 61 00 68 00 6f 00 73 00 74 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 61 00 66 00 65 00 5f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00 } //2 http://lapapahoster.com/safe_download/
		$a_01_1 = {41 00 64 00 73 00 53 00 68 00 6f 00 77 00 2e 00 65 00 78 00 65 00 } //1 AdsShow.exe
		$a_01_2 = {57 00 43 00 6d 00 6f 00 75 00 69 00 54 00 72 00 69 00 2e 00 65 00 78 00 65 00 } //1 WCmouiTri.exe
		$a_01_3 = {5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 57 00 43 00 6d 00 6f 00 75 00 69 00 54 00 72 00 69 00 2e 00 70 00 64 00 62 00 } //1 \Release\WCmouiTri.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}