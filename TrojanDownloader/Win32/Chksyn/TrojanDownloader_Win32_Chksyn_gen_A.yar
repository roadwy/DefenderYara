
rule TrojanDownloader_Win32_Chksyn_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Chksyn.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {00 00 53 56 57 6a 04 be 00 30 00 00 56 ff 35 00 20 11 13 6a 00 e8 } //1
		$a_02_1 = {68 ae d0 16 ab e8 ?? 00 00 00 50 e8 ?? 00 00 00 ff 74 24 10 ff 74 24 10 ff 74 24 10 ff 74 24 10 ff d0 c3 } //1
		$a_02_2 = {68 84 9b 50 f2 e8 ?? fe ff ff 50 e8 ?? fe ff ff ff 74 24 08 ff 74 24 08 ff d0 c3 } //1
		$a_00_3 = {c1 c2 03 32 10 40 80 38 00 0f } //1
		$a_02_4 = {64 a1 30 00 00 00 0f ?? ?? 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}