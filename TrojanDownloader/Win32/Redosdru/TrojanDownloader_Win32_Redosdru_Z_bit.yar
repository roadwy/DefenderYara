
rule TrojanDownloader_Win32_Redosdru_Z_bit{
	meta:
		description = "TrojanDownloader:Win32/Redosdru.Z!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 0c 4b c6 44 24 0d 6f c6 44 24 0e 74 c6 44 24 0f 68 c6 44 24 10 65 c6 44 24 11 72 c6 44 24 12 35 c6 44 24 15 00 } //1
		$a_01_1 = {c6 44 24 14 47 c6 44 24 15 65 c6 44 24 16 74 c6 44 24 17 6f c6 44 24 18 6e c6 44 24 19 67 c6 44 24 1a 35 c6 44 24 1b 33 c6 44 24 1c 38 } //1
		$a_03_2 = {8b 4c 24 0c 8a 14 08 80 c2 90 01 01 88 14 08 8b 4c 24 0c 8a 14 08 80 f2 90 01 01 88 14 08 40 3b c6 7c 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}