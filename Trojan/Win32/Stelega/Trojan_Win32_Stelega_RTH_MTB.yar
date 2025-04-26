
rule Trojan_Win32_Stelega_RTH_MTB{
	meta:
		description = "Trojan:Win32/Stelega.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 07 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 29 df 4f e8 ?? ?? ?? ?? 21 db 01 df 81 eb 01 96 0a 95 31 02 89 df } //1
		$a_03_1 = {29 f6 09 f3 e8 ?? ?? ?? ?? 4e 31 0a 83 ec 04 89 1c 24 5b 42 83 ec 04 } //1
		$a_03_2 = {47 09 ff b9 27 bb 51 b1 e8 ?? ?? ?? ?? 29 c9 09 f9 31 32 89 f9 89 c9 09 } //1
		$a_00_3 = {81 ee 6d 4e 6c c5 31 13 21 c9 81 ee 36 45 63 b5 21 f6 43 29 f6 41 39 c3 75 d3 } //1
		$a_00_4 = {bb 4a f8 f9 b9 89 db 31 10 bb bf 0d ac 94 21 fb 81 ef 88 d1 bd 87 40 21 fb } //1
		$a_03_5 = {81 ea 1d eb ee 56 e8 ?? ?? ?? ?? 40 21 d0 31 0f 21 d2 21 c2 48 47 81 e8 } //1
		$a_03_6 = {ba c2 d6 f7 9b e8 ?? ?? ?? ?? 21 c2 21 c0 48 31 19 81 c0 e7 16 00 82 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1) >=1
 
}