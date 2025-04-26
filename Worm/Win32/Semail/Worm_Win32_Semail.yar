
rule Worm_Win32_Semail{
	meta:
		description = "Worm:Win32/Semail,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 0a 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4b 61 7a 61 61 } //1 SOFTWARE\Kazaa
		$a_01_1 = {6f 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 47 65 74 4e 61 6d 65 73 70 61 63 65 28 27 4d 41 50 49 27 29 } //2 ol.Application.GetNamespace('MAPI')
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 41 42 5c 44 4c 4c 50 61 74 68 } //2 Software\Microsoft\WAB\DLLPath
		$a_00_3 = {63 6d 64 20 2f 43 20 63 73 63 72 69 70 74 } //1 cmd /C cscript
		$a_00_4 = {25 73 2c 20 25 64 20 25 73 20 25 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 } //2 %s, %d %s %d %02d:%02d:%02d
		$a_00_5 = {3d 3f 69 73 6f 2d 38 38 35 39 2d 31 3f 51 3f } //1 =?iso-8859-1?Q?
		$a_00_6 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c 25 73 3e } //1 MAIL FROM:<%s>
		$a_00_7 = {52 43 50 54 20 54 4f 3a 3c 25 73 3e } //1 RCPT TO:<%s>
		$a_00_8 = {6e 6f 62 6f 64 79 40 6e 6f 77 68 65 72 65 2e 63 6f 6d } //2 nobody@nowhere.com
		$a_00_9 = {81 3e 1e 00 01 30 75 18 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*2+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*2+(#a_00_9  & 1)*2) >=12
 
}