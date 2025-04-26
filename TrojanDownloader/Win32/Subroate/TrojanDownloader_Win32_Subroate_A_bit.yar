
rule TrojanDownloader_Win32_Subroate_A_bit{
	meta:
		description = "TrojanDownloader:Win32/Subroate.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 01 56 8b f2 84 c0 74 0e 2b ca 34 7f 88 02 42 8a 04 11 84 c0 75 f4 8b c6 c6 02 00 5e c3 } //1
		$a_01_1 = {00 53 74 75 62 2e 64 6c 6c 00 5f 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}