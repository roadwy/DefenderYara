
rule TrojanDownloader_Win32_Delf_ZXZ_bit{
	meta:
		description = "TrojanDownloader:Win32/Delf.ZXZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 2d ?? ?? ?? ?? d1 e8 8b 4d ?? 8b 55 ?? 66 8b 04 45 ?? ?? ?? ?? 66 89 04 4a 8b 45 ?? 40 89 45 ?? eb } //1
		$a_01_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 20 00 2f 00 71 00 20 00 2f 00 69 00 } //1 msiexec /q /i
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}