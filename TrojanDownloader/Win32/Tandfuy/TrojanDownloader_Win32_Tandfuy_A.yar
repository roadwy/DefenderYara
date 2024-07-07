
rule TrojanDownloader_Win32_Tandfuy_A{
	meta:
		description = "TrojanDownloader:Win32/Tandfuy.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6e 65 74 20 73 74 6f 70 20 4d 73 4d 70 53 76 63 } //1 net stop MsMpSvc
		$a_00_1 = {00 5c 75 6e 69 6e 73 30 30 30 2e 61 79 65 00 } //1
		$a_03_2 = {85 c0 75 04 83 c4 90 01 01 c3 8b 4c 24 90 01 01 53 6a 00 6a 00 6a 00 6a 00 51 50 ff 15 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}