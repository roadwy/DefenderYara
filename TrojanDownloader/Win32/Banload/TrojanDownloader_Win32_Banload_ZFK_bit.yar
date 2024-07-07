
rule TrojanDownloader_Win32_Banload_ZFK_bit{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZFK!bit,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 4c 6f 63 61 6c 65 73 } //10 Software\Borland\Delphi\Locales
		$a_03_1 = {7d 03 46 eb 02 33 f6 8b 45 f8 8a 44 30 ff 88 45 90 01 01 8a 45 90 01 01 30 45 90 01 01 8b c7 03 c3 89 45 90 01 01 8d 55 90 01 01 b9 90 01 03 00 8b 45 90 01 01 e8 90 01 03 ff 43 3b 5d fc 7c b2 90 00 } //2
		$a_03_2 = {8b 55 e4 58 e8 90 01 03 ff 8b 4d ec b8 90 01 03 00 8b d3 e8 90 01 03 ff b8 90 01 03 00 8b d3 e8 90 01 03 ff 90 00 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1) >=13
 
}