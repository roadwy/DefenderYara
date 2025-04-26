
rule TrojanClicker_Win32_Delf_BC{
	meta:
		description = "TrojanClicker:Win32/Delf.BC,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {ff 8d 45 f8 ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 55 f8 58 e8 ?? ?? ?? ff 0f 84 91 00 00 00 8d 45 f4 e8 ?? ?? ?? ff 8d 45 f4 ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 45 f4 e8 ?? ?? ?? ff 84 c0 75 70 e8 ?? ?? ?? ff 6a 00 8d 45 f0 e8 ?? ?? ?? ff 8d 45 f0 ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 45 f0 e8 ?? ?? ?? ff 50 8d 55 ec 33 c0 e8 ?? ?? ?? ff 8b 45 ec e8 ?? ?? ?? ff 50 e8 ?? ?? ?? ff 6a 00 6a 00 68 ?? ?? ?? 00 8d 45 e8 e8 ?? ?? ?? ff 8d 45 e8 ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 45 e8 e8 ?? ?? ?? ff 50 68 ?? ?? ?? 00 6a 00 e8 } //1
		$a_00_1 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //1 \Software\Microsoft\Internet Explorer\Main
		$a_00_2 = {53 65 72 76 69 63 65 41 66 74 65 72 49 6e 73 74 61 6c 6c } //1 ServiceAfterInstall
		$a_00_3 = {70 6f 70 75 70 2e 70 68 70 3f } //1 popup.php?
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}