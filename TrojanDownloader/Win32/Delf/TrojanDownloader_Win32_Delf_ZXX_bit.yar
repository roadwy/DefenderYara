
rule TrojanDownloader_Win32_Delf_ZXX_bit{
	meta:
		description = "TrojanDownloader:Win32/Delf.ZXX!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 22 bb 01 00 00 00 8d 45 ?? e8 ?? ?? ?? ?? 8b 55 ?? 0f b7 54 5a fe 66 83 f2 ?? 66 89 54 58 fe 43 4e 75 e3 } //1
		$a_03_1 = {6a 05 6a 00 6a 00 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 6a 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}