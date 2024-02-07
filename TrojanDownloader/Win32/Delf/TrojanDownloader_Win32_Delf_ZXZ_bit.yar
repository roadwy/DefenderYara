
rule TrojanDownloader_Win32_Delf_ZXZ_bit{
	meta:
		description = "TrojanDownloader:Win32/Delf.ZXZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 2d 90 01 04 d1 e8 8b 4d 90 01 01 8b 55 90 01 01 66 8b 04 45 90 01 04 66 89 04 4a 8b 45 90 01 01 40 89 45 90 01 01 eb 90 00 } //01 00 
		$a_01_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 20 00 2f 00 71 00 20 00 2f 00 69 00 } //00 00  msiexec /q /i
	condition:
		any of ($a_*)
 
}