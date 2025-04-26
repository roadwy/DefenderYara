
rule TrojanClicker_Win32_Olafre_A{
	meta:
		description = "TrojanClicker:Win32/Olafre.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 63 62 6c 2e 74 6f 6f 6c 62 61 72 34 66 72 65 65 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 73 2e 65 78 65 } //1 http://cbl.toolbar4free.com/cgi-bin/s.exe
		$a_03_1 = {64 ff 30 64 89 20 8b d6 b8 ?? ?? 45 00 e8 ?? ?? ?? ff 85 c0 7e 0c 8d 45 ?? 8b d6 e8 ?? ?? ?? ff eb 0f 8d 45 fc 8b ce ba ?? ?? 45 00 e8 ?? ?? ?? ff 84 db 0f 84 1e 01 00 00 6a 00 8d 45 ?? 50 33 c9 ba ?? ?? 45 00 b8 00 00 00 80 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}