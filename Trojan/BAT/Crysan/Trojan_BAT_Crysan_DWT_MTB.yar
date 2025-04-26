
rule Trojan_BAT_Crysan_DWT_MTB{
	meta:
		description = "Trojan:BAT/Crysan.DWT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {69 61 6d 6b 69 6e 67 67 } //1 iamkingg
		$a_81_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_2 = {47 65 74 53 74 72 69 6e 67 } //1 GetString
		$a_81_3 = {79 61 72 72 61 6d } //1 yarram
		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_80_5 = {57 65 62 43 6c 69 65 6e 74 } //WebClient  1
		$a_01_6 = {6c 00 61 00 75 00 72 00 65 00 6e 00 74 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 6f 00 72 00 2e 00 63 00 6f 00 6d 00 2f 00 62 00 69 00 6e 00 6c 00 65 00 72 00 2f 00 } //1 laurentprotector.com/binler/
		$a_01_7 = {4e 00 79 00 57 00 4e 00 73 00 4b 00 55 00 4f 00 55 00 49 00 56 00 5a 00 7a 00 42 00 4e 00 } //1 NyWNsKUOUIVZzBN
		$a_01_8 = {50 00 52 00 6d 00 6f 00 62 00 68 00 4f 00 4b 00 5a 00 45 00 5a 00 4b 00 42 00 76 00 58 00 2e 00 4c 00 75 00 55 00 6e 00 63 00 47 00 7a 00 71 00 45 00 77 00 45 00 70 00 4e 00 73 00 6a 00 } //1 PRmobhOKZEZKBvX.LuUncGzqEwEpNsj
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_80_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}