
rule TrojanDownloader_Win32_Rudeflate_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Rudeflate.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 01 00 00 00 8b 0d ?? ?? ?? ?? 80 74 01 ff ?? 40 4a 75 f1 } //1
		$a_03_1 = {8b d8 c7 43 08 0f 00 00 00 83 ce ff 66 b9 50 00 8b 55 ?? 8b c3 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}