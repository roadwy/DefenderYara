
rule TrojanDownloader_Win32_Fosniw_C{
	meta:
		description = "TrojanDownloader:Win32/Fosniw.C,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 70 70 2e 69 65 6b 65 79 77 6f 72 64 2e 63 6f 6d } //1 app.iekeyword.com
		$a_01_1 = {61 70 70 2e 6b 65 79 77 6f 72 64 6b 72 2e 63 6f 6d } //1 app.keywordkr.com
		$a_01_2 = {61 70 70 78 2e 6b 6f 72 65 61 73 79 73 31 2e 63 6f 6d } //1 appx.koreasys1.com
		$a_03_3 = {2f 72 65 63 65 69 76 65 2f 72 5f 61 75 74 6f 69 64 63 6e 74 2e 61 73 70 3f 6d 65 72 5f 73 65 71 3d 25 73 26 72 65 61 6c 69 64 3d 25 73 26 63 6e 74 5f 74 79 70 65 3d [0-02] 26 6d 61 63 3d 25 73 } //5
		$a_01_4 = {3f 70 72 6a 3d 25 73 26 70 69 64 3d 25 73 26 6d 61 63 3d 25 73 26 6c 6f 67 64 61 74 61 3d 4d 61 63 54 72 79 43 6e 74 3a 25 64 26 63 6f 64 65 3d 25 73 26 76 65 72 3d 25 73 } //5 ?prj=%s&pid=%s&mac=%s&logdata=MacTryCnt:%d&code=%s&ver=%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*5+(#a_01_4  & 1)*5) >=11
 
}