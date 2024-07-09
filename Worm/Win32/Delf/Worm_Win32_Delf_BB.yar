
rule Worm_Win32_Delf_BB{
	meta:
		description = "Worm:Win32/Delf.BB,SIGNATURE_TYPE_PEHSTR_EXT,48 00 47 00 09 00 00 "
		
	strings :
		$a_02_0 = {84 c0 75 33 6a 00 68 ?? ?? 45 00 8d 55 d8 a1 e8 40 45 00 8b 00 e8 ?? ?? ?? ff 8b 45 d8 e8 ?? ?? ?? ff 50 e8 ?? ?? ?? ff ba 05 00 00 00 b8 ?? ?? 45 00 e8 ?? ?? ?? ff b8 ?? ?? 45 00 e8 08 f8 ff ff 84 c0 0f 84 a5 00 00 00 8d 45 f0 ba 78 1d 45 00 e8 ?? ?? ?? ff b2 01 a1 74 71 42 00 e8 ?? ?? ?? ff 89 45 f4 33 c0 55 68 ?? ?? 45 00 64 ff 30 64 89 20 8d 45 f8 } //10
		$a_02_1 = {84 c0 75 67 6a 00 8d 85 d8 fe ff ff b9 ?? ?? 45 00 8b 55 fc e8 ?? ?? fb ff 8b 85 d8 fe ff ff e8 ?? ?? fb ff 50 8d 95 d4 fe ff ff a1 ?? ?? 45 00 8b 00 e8 ?? ?? ?? ?? 8b 85 d4 fe ff ff e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8d 85 d0 fe ff ff b9 ?? ?? 45 00 8b 55 fc e8 ?? ?? ?? ?? 8b 85 d0 fe ff ff ba 07 00 00 00 e8 ?? ?? ?? ?? 8d 85 cc fe ff ff b9 ?? ?? 45 00 8b 55 fc } //10
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_00_3 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //10 :\autorun.inf
		$a_00_4 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //10 \Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_5 = {4d 65 6e 75 20 49 6e 69 63 69 61 72 5c 50 72 6f 67 72 61 6d 61 73 5c 49 6e 69 63 69 61 6c 69 7a 61 72 5c 77 69 6e 73 79 73 32 2e 65 78 65 } //10 Menu Iniciar\Programas\Inicializar\winsys2.exe
		$a_00_6 = {3a 5c 77 69 6e 73 79 73 32 2e 65 78 65 } //10 :\winsys2.exe
		$a_00_7 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 65 74 75 70 2e 69 6e 69 } //1 C:\WINDOWS\setup.ini
		$a_00_8 = {68 74 74 70 3a 2f 2f 73 65 67 75 72 69 74 79 73 79 73 2e 6b 69 6e 67 68 6f 73 74 2e 6e 65 74 2f 3f 69 64 3d 31 } //1 http://seguritysys.kinghost.net/?id=1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*10+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=71
 
}