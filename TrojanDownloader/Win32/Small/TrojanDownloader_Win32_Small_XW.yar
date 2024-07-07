
rule TrojanDownloader_Win32_Small_XW{
	meta:
		description = "TrojanDownloader:Win32/Small.XW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {77 00 68 00 72 00 74 00 65 00 6e 00 67 00 90 09 22 00 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 90 00 } //1
		$a_01_1 = {69 00 72 00 69 00 6e 00 67 00 34 00 75 00 2e 00 63 00 6f 00 2e 00 6b 00 72 00 2f 00 61 00 64 00 37 00 39 00 64 00 6f 00 77 00 6e 00 2f 00 73 00 74 00 69 00 70 00 73 00 65 00 74 00 75 00 70 00 } //1 iring4u.co.kr/ad79down/stipsetup
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}