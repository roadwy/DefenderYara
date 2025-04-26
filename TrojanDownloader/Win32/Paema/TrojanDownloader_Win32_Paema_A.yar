
rule TrojanDownloader_Win32_Paema_A{
	meta:
		description = "TrojanDownloader:Win32/Paema.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 44 24 28 50 e8 ?? ?? ?? ?? 59 84 c0 74 07 68 ?? ?? ?? ?? eb 05 68 ?? ?? ?? ?? ff d6 eb e1 } //1
		$a_01_1 = {f7 f3 8b 4f 14 89 4d ec d1 6d ec 8b 55 ec 3b d0 76 0e 8b 75 e8 8b c6 2b c2 3b c8 77 03 8d 34 0a 83 65 fc 00 8d 46 01 50 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}