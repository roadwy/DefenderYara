
rule TrojanDownloader_Win32_Cutwail_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 5a 74 0a ba ff ff ff ff e9 ?? ?? 00 00 83 ec ?? 8d ?? d8 fe ff ff 90 09 07 00 80 ?? 4d 75 06 80 } //1
		$a_03_1 = {74 14 83 ec 08 89 d8 29 d0 50 8d 04 16 50 e8 ?? ?? 00 00 83 c4 10 e8 ?? 00 00 00 b8 00 00 00 00 } //1
		$a_01_2 = {75 7f 8a 44 3e 01 30 04 3e 8a 54 3e 02 31 d0 88 44 3e 01 8a 44 3e 03 31 c2 88 54 3e 02 40 88 44 3e 03 56 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}