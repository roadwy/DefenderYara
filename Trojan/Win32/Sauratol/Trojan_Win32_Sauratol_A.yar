
rule Trojan_Win32_Sauratol_A{
	meta:
		description = "Trojan:Win32/Sauratol.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 09 00 0b 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 63 20 64 65 6c 20 22 43 3a 5c 6d 79 61 70 70 2e 65 78 65 } //01 00  /c del "C:\myapp.exe
		$a_01_1 = {3c 49 46 52 41 4d 45 20 53 52 43 3d 22 48 54 54 50 3a 2f 2f 77 77 77 2e } //01 00  <IFRAME SRC="HTTP://www.
		$a_00_2 = {68 74 6d 2d 68 74 6d 6c 2d 61 73 70 2d 61 73 70 78 2d 70 68 70 } //01 00  htm-html-asp-aspx-php
		$a_00_3 = {77 77 77 2e 79 73 62 72 2e 63 6e } //01 00  www.ysbr.cn
		$a_00_4 = {57 49 44 54 48 3d 30 20 48 45 49 47 48 54 3d 30 3e 3c 2f 49 46 52 41 4d 45 3e } //01 00  WIDTH=0 HEIGHT=0></IFRAME>
		$a_00_5 = {73 76 63 68 6f 73 74 2e 65 78 65 } //01 00  svchost.exe
		$a_00_6 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 5c 78 32 30 5c 78 30 30 } //01 00  C:\WINDOWS\SYSTE\x20\x00
		$a_00_7 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 } //01 00  C:\WINDOWS\SYSTEM32
		$a_00_8 = {52 65 6d 6f 74 65 20 48 65 6c 70 20 53 65 73 73 69 6f 6e 20 4d 61 6e 61 67 65 72 } //01 00  Remote Help Session Manager
		$a_00_9 = {52 61 73 61 75 74 6f 6c } //01 00  Rasautol
		$a_00_10 = {2f 63 20 64 65 6c 20 22 43 3a 5c 2f 63 } //00 00  /c del "C:\/c
	condition:
		any of ($a_*)
 
}