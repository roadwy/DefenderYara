
rule TrojanDownloader_Win32_Agent_AAT{
	meta:
		description = "TrojanDownloader:Win32/Agent.AAT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 63 64 73 73 73 2e 65 78 65 } //1 \cdsss.exe
		$a_00_1 = {5c 76 6e 38 38 2e 65 78 65 } //1 \vn88.exe
		$a_02_2 = {2f 6d 69 6d 2f 90 04 04 0a 30 31 32 33 34 35 36 37 38 39 2e 65 78 65 90 0a 40 00 68 74 74 70 3a 2f 2f } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}