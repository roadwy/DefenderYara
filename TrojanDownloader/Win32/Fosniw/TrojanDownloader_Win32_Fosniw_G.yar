
rule TrojanDownloader_Win32_Fosniw_G{
	meta:
		description = "TrojanDownloader:Win32/Fosniw.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 2e 6b 65 79 77 6f 72 64 6b 72 2e 63 6f 6d 2f } //1 p.keywordkr.com/
		$a_01_1 = {2f 72 65 63 65 69 76 65 2f 72 5f 61 75 74 6f 69 64 63 6e 74 2e 61 73 70 3f 6d 65 72 5f 73 65 71 3d 25 73 26 72 65 61 6c 69 64 3d 25 73 26 63 6e 74 5f 74 79 70 65 3d 65 38 26 6d 61 63 3d 25 73 } //1 /receive/r_autoidcnt.asp?mer_seq=%s&realid=%s&cnt_type=e8&mac=%s
		$a_01_2 = {3f 70 72 6a 3d 25 73 26 70 69 64 3d 25 73 26 71 79 3d 25 73 26 6d 61 63 3d 25 73 26 77 3d 25 64 26 68 3d 25 64 } //1 ?prj=%s&pid=%s&qy=%s&mac=%s&w=%d&h=%d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}