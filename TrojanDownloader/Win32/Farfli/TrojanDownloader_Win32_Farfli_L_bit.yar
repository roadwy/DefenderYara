
rule TrojanDownloader_Win32_Farfli_L_bit{
	meta:
		description = "TrojanDownloader:Win32/Farfli.L!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 14 08 80 c2 ?? 88 14 08 8b 4c 24 08 8a 14 08 80 f2 ?? 88 14 08 40 3b c6 7c } //1
		$a_01_1 = {81 ca 00 ff ff ff 42 8a 14 02 8a 1c 2f 32 da 8b 54 24 1c 88 1c 2f 47 3b fa 72 } //2
		$a_03_2 = {4b c6 44 24 ?? 6f c6 44 24 ?? 74 c6 44 24 ?? 68 c6 44 24 ?? 65 c6 44 24 ?? 72 c6 44 24 ?? 35 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1) >=3
 
}