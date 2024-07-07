
rule TrojanDownloader_Win32_Banload_FZ{
	meta:
		description = "TrojanDownloader:Win32/Banload.FZ,SIGNATURE_TYPE_PEHSTR_EXT,39 00 37 00 0c 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {62 65 6e 63 6b 79 6c 2e 63 6f 6d 2f 61 63 65 73 73 6f 2e 70 68 70 } //10 benckyl.com/acesso.php
		$a_00_2 = {77 77 77 2e 64 69 6e 61 6d 69 63 61 6c 74 64 61 2e 63 6f 6d 2e 62 72 2f 77 69 6e 64 6f 77 73 5f 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //10 www.dinamicaltda.com.br/windows_installer.exe
		$a_02_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 90 02 10 53 74 61 72 74 20 50 61 67 65 90 00 } //10
		$a_00_4 = {55 75 69 64 43 72 65 61 74 65 53 65 71 75 65 6e 74 69 61 6c } //10 UuidCreateSequential
		$a_00_5 = {63 6f 6d 70 75 74 61 64 6f 72 3d } //1 computador=
		$a_00_6 = {75 73 75 61 72 69 6f 3d } //1 usuario=
		$a_00_7 = {73 68 64 5f 66 69 73 69 63 6f 3d } //1 shd_fisico=
		$a_00_8 = {73 68 64 5f 66 69 72 6d 77 61 72 65 3d } //1 shd_firmware=
		$a_00_9 = {77 69 6e 64 69 72 3d } //1 windir=
		$a_00_10 = {6d 61 63 3d } //1 mac=
		$a_00_11 = {70 61 67 5f 69 6e 69 63 3d } //1 pag_inic=
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_02_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1) >=55
 
}