
rule TrojanDownloader_Win64_AsyncRat_CEB_MTB{
	meta:
		description = "TrojanDownloader:Win64/AsyncRat.CEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {f3 0f 7f 4c 24 90 01 01 66 c7 44 24 90 02 04 66 0f 6f 0d 90 01 01 20 00 00 f3 0f 7f 44 24 90 01 01 c6 44 24 90 01 02 f3 0f 7f 4c 24 90 02 03 c7 44 24 90 02 0a 48 c7 44 24 20 00 00 00 00 ff 90 00 } //01 00 
		$a_01_1 = {5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 57 65 63 68 61 74 41 6e 64 2e 70 64 62 } //01 00  \x64\Release\WechatAnd.pdb
		$a_01_2 = {5c 00 63 00 6f 00 64 00 65 00 2e 00 62 00 69 00 6e 00 } //01 00  \code.bin
		$a_01_3 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 } //00 00  WindowsProject1
	condition:
		any of ($a_*)
 
}