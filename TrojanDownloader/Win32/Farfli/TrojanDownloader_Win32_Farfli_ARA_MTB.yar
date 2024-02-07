
rule TrojanDownloader_Win32_Farfli_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Farfli.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 73 68 65 6c 6c 63 6f 64 65 5c 52 65 6c 65 61 73 65 5c 73 68 65 6c 6c 63 6f 64 65 2e 70 64 62 } //02 00  \shellcode\Release\shellcode.pdb
		$a_03_1 = {0f b6 06 53 50 e8 90 01 04 88 06 83 c4 08 46 3b f7 75 ec 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}