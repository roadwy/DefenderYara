
rule TrojanDownloader_Win32_Small_ZYN{
	meta:
		description = "TrojanDownloader:Win32/Small.ZYN,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {69 c0 00 a4 93 d6 50 ff 15 ?? ?? ?? ?? 8b 45 f0 c6 45 fc 04 3b c3 74 06 } //1
		$a_01_1 = {25 73 5c 31 32 32 39 2e 74 6d 70 } //1 %s\1229.tmp
		$a_03_2 = {5c 56 4c 2e 69 6e 69 90 09 0a 00 43 3a 5c 57 49 4e 44 4f 57 53 } //1
		$a_01_3 = {6a 6a 2e 37 36 35 33 32 31 2e 69 6e 66 6f 3a 33 32 31 38 2f 73 6d 73 2f 78 78 78 30 32 2e 69 6e 69 } //1 jj.765321.info:3218/sms/xxx02.ini
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}