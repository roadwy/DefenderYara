
rule TrojanDownloader_Win32_Dofoil_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 c9 74 16 49 74 13 ba 90 01 04 8b 75 08 4a ac 32 07 aa 90 00 } //1
		$a_01_1 = {8b 4e 50 c1 e9 02 31 c0 f3 ab 0f b7 5e 06 b8 28 00 00 00 f7 e3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}