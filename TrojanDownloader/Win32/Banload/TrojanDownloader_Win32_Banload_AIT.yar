
rule TrojanDownloader_Win32_Banload_AIT{
	meta:
		description = "TrojanDownloader:Win32/Banload.AIT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {ff 5e 5b c3 00 00 00 ff ff ff ff 0f 00 00 00 43 3a 5c 50 72 6f 67 72 61 6d 64 61 74 61 5c 00 } //1
		$a_02_1 = {2e 73 69 74 65 73 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 2f [0-40] 2e 73 77 66 00 00 07 54 42 75 74 74 6f 6e 07 42 75 74 74 6f 6e 32 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}