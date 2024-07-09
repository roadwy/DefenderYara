
rule TrojanDownloader_Win32_Drstwex_C{
	meta:
		description = "TrojanDownloader:Win32/Drstwex.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {50 8b f8 8b 4d f0 83 f9 00 74 ?? 8b 75 f4 f3 a4 8b 4d f8 8b 75 fc f3 a4 8b 45 f0 03 45 f8 89 45 f0 68 00 80 00 00 6a 00 ff 75 f4 } //1
		$a_00_1 = {50 8b 00 8b d0 c1 e0 02 33 c2 05 85 00 00 00 5a 89 02 c1 e8 18 5a c3 } //1
		$a_02_2 = {83 f8 00 0f 85 ?? ?? ?? ?? 6a 00 6a 07 68 08 09 10 00 ff 35 ?? ?? ?? ?? e8 27 ff ff ff 8d 45 f8 50 8d 45 fc 50 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}