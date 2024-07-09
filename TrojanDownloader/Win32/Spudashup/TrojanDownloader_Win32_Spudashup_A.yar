
rule TrojanDownloader_Win32_Spudashup_A{
	meta:
		description = "TrojanDownloader:Win32/Spudashup.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {61 00 64 00 73 00 65 00 72 00 76 00 65 00 72 00 [0-06] 2e 00 66 00 69 00 6c 00 65 00 61 00 76 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 68 00 6f 00 77 00 61 00 64 00 73 00 2e 00 68 00 74 00 6d 00 6c 00 } //1
		$a_01_1 = {73 69 6c 65 6e 74 00 00 73 68 6f 77 74 69 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}