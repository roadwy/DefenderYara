
rule TrojanDownloader_Win32_Banload_ZFL_bit{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZFL!bit,SIGNATURE_TYPE_PEHSTR_EXT,7a 00 7a 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 4c 6f 63 61 6c 65 73 } //100 Software\Borland\Delphi\Locales
		$a_03_1 = {62 61 74 65 72 69 61 73 74 69 74 75 6c 61 72 [0-20] 63 6f 6d [0-20] 62 72 } //10
		$a_03_2 = {6d 6f 64 65 72 6e 2d 63 6f 6c 6c 65 67 65 [0-20] 61 6d 69 77 6f 72 6b 73 } //10
		$a_01_3 = {46 6c 69 6f 6e 31 32 33 } //1 Flion123
		$a_01_4 = {4a 55 4a 55 42 41 30 33 } //1 JUJUBA03
		$a_03_5 = {8d 45 d0 e8 ?? ?? ?? ff ff 75 d0 8d 45 cc e8 ?? ?? ?? ff ff 75 cc 8d 45 c8 e8 ?? ?? ?? ff ff 75 c8 8d 45 f8 ba 0c 00 00 00 e8 ?? ?? ?? ff 8b 45 f8 8d 55 fc e8 ?? ?? ?? ff 8b 55 fc 8b c6 e8 ?? ?? ?? ff b8 ?? ?? ?? 00 ba ?? ?? ?? 00 e8 ?? ?? ?? ff } //2
	condition:
		((#a_00_0  & 1)*100+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*2) >=122
 
}