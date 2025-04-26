
rule Trojan_Win32_Neoreblamy_ASZ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {63 66 75 47 48 57 4b 6f 48 51 53 4c 6e 59 57 78 6a 77 72 6f 4a 62 4e 48 62 62 61 4f } //1 cfuGHWKoHQSLnYWxjwroJbNHbbaO
		$a_01_1 = {54 6d 54 52 56 75 70 6b 48 55 56 77 74 41 66 79 49 68 53 53 53 50 68 58 53 52 74 48 } //1 TmTRVupkHUVwtAfyIhSSSPhXSRtH
		$a_01_2 = {72 62 65 75 59 59 77 75 78 4b 67 48 67 77 6e 64 6c 58 6a 53 4b 71 6f 43 4e 6c 44 52 79 79 57 69 67 4e } //1 rbeuYYwuxKgHgwndlXjSKqoCNlDRyyWigN
		$a_01_3 = {47 50 70 6f 6f 71 4a 52 63 6b 59 55 54 6c 62 46 4e 59 4c 50 4e 41 4c 4e 79 79 50 48 63 } //1 GPpooqJRckYUTlbFNYLPNALNyyPHc
		$a_01_4 = {72 76 66 43 70 66 57 6e 71 79 48 42 70 72 4c 42 55 4e 67 50 64 4d 63 66 62 7a 4b 58 67 67 } //1 rvfCpfWnqyHBprLBUNgPdMcfbzKXgg
		$a_01_5 = {75 78 61 52 79 6d 57 70 52 56 67 4c 5a 49 56 46 7a 61 68 64 66 45 74 6e 76 4c 6a 55 70 78 } //1 uxaRymWpRVgLZIVFzahdfEtnvLjUpx
		$a_01_6 = {52 45 69 61 79 77 7a 77 53 46 55 47 61 44 7a 44 76 68 50 67 75 6b 42 59 48 52 53 55 } //1 REiaywzwSFUGaDzDvhPgukBYHRSU
		$a_01_7 = {4b 6b 47 59 7a 66 71 57 55 50 70 53 47 52 50 45 7a 42 71 70 4c 4d 67 51 4c 4c 72 58 76 6a 66 73 67 4e } //1 KkGYzfqWUPpSGRPEzBqpLMgQLLrXvjfsgN
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=4
 
}