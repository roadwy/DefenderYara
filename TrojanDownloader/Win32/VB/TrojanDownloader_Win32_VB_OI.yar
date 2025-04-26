
rule TrojanDownloader_Win32_VB_OI{
	meta:
		description = "TrojanDownloader:Win32/VB.OI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5f 00 6d 00 75 00 63 00 6f 00 64 00 65 00 2e 00 62 00 61 00 6b 00 } //1 _mucode.bak
		$a_01_1 = {2e 00 73 00 61 00 76 00 65 00 32 00 31 00 2e 00 70 00 65 00 2e 00 6b 00 72 00 } //1 .save21.pe.kr
		$a_01_2 = {2e 00 73 00 6f 00 69 00 69 00 32 00 31 00 2e 00 70 00 65 00 2e 00 6b 00 72 00 } //1 .soii21.pe.kr
		$a_01_3 = {2f 00 75 00 73 00 65 00 72 00 68 00 69 00 73 00 74 00 6f 00 72 00 79 00 2f 00 75 00 73 00 65 00 72 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 61 00 6c 00 6c 00 5f 00 63 00 6f 00 6d 00 2e 00 61 00 73 00 70 00 } //1 /userhistory/userconnectall_com.asp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}