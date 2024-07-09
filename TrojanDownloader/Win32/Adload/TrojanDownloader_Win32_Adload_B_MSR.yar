
rule TrojanDownloader_Win32_Adload_B_MSR{
	meta:
		description = "TrojanDownloader:Win32/Adload.B!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {4a 4a 44 6f 77 6e 4c 6f 61 64 65 72 5c 42 69 6e 5c 4a 4a 44 6f 77 6e 4c 6f 61 64 65 72 5f 61 2e 70 64 62 } //1 JJDownLoader\Bin\JJDownLoader_a.pdb
		$a_02_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-20] 2f 00 67 00 65 00 74 00 73 00 6f 00 66 00 74 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}