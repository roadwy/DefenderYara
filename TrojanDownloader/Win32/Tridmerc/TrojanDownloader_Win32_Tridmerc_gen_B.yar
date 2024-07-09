
rule TrojanDownloader_Win32_Tridmerc_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Tridmerc.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c1 e6 02 b8 65 89 07 6c } //1
		$a_01_1 = {c1 e6 07 81 e6 80 56 2c 9d 31 f7 89 fe c1 e6 0f 81 e6 00 00 c6 ef } //1
		$a_03_2 = {75 2c 6a 00 8d 85 d8 fd ff ff 50 e8 ?? ?? 00 00 83 f8 1f 76 00 8d 85 d8 fd ff ff 50 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}