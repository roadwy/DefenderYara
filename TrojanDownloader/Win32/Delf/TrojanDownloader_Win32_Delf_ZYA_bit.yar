
rule TrojanDownloader_Win32_Delf_ZYA_bit{
	meta:
		description = "TrojanDownloader:Win32/Delf.ZYA!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 fc 0f b7 54 7a fe 66 3b 10 75 25 8d 85 90 01 03 ff 0f b7 13 e8 90 01 03 ff 8b 95 90 01 03 ff 8b 45 f8 e8 90 01 03 ff 8b 45 f8 c6 45 90 01 01 01 eb 09 83 c3 02 83 c0 02 4e 75 c5 90 00 } //2
		$a_03_1 = {6a 05 6a 00 6a 00 a1 90 01 03 00 e8 90 01 03 ff 50 68 90 01 03 00 6a 00 e8 90 01 03 ff 8d 55 d8 b8 90 01 03 00 e8 90 01 03 ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}