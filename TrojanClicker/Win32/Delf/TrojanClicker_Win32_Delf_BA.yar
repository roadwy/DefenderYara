
rule TrojanClicker_Win32_Delf_BA{
	meta:
		description = "TrojanClicker:Win32/Delf.BA,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_02_0 = {84 c0 75 1d 6a 00 6a 00 8b 45 ?? e8 ?? ?? ?? ff 50 8b 45 ?? e8 ?? ?? ?? ff 50 6a 00 e8 ?? ?? ?? ff 8d 45 ?? ba ?? ?? ?? 00 e8 ?? ?? ?? ff [0-0d] 8d 85 ?? ff ff ff 8d 95 ?? ff ff ff b9 81 00 00 00 e8 ?? ?? ?? ff 8b 95 ?? ff ff ff 8d 45 ?? b9 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 45 ?? e8 ?? ?? ?? ff 84 c0 } //10
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_00_2 = {5c 74 61 73 6b 6d 6f 72 2e 65 78 65 } //1 \taskmor.exe
		$a_00_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 77 7a 64 71 2e 63 6e 2f 73 66 } //1 http://www.wzdq.cn/sf
		$a_00_4 = {5c 77 69 6e 6c 6f 67 69 6e 2e 65 78 65 } //1 \winlogin.exe
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=21
 
}