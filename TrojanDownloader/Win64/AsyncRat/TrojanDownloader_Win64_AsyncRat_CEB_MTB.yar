
rule TrojanDownloader_Win64_AsyncRat_CEB_MTB{
	meta:
		description = "TrojanDownloader:Win64/AsyncRat.CEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {f3 0f 7f 4c 24 ?? 66 c7 44 24 [0-04] 66 0f 6f 0d ?? 20 00 00 f3 0f 7f 44 24 ?? c6 44 24 ?? ?? f3 0f 7f 4c 24 [0-03] c7 44 24 [0-0a] 48 c7 44 24 20 00 00 00 00 ff } //5
		$a_01_1 = {5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 57 65 63 68 61 74 41 6e 64 2e 70 64 62 } //1 \x64\Release\WechatAnd.pdb
		$a_01_2 = {5c 00 63 00 6f 00 64 00 65 00 2e 00 62 00 69 00 6e 00 } //1 \code.bin
		$a_01_3 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 } //1 WindowsProject1
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}