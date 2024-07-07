
rule Worm_Win32_Delf_BT{
	meta:
		description = "Worm:Win32/Delf.BT,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 29 00 07 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //10 Software\Borland\Delphi
		$a_00_1 = {5b 61 75 74 6f 72 75 6e 5d } //10 [autorun]
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 54 79 70 65 64 } //10 Software\Microsoft\Internet Explorer\Typed
		$a_02_3 = {52 45 47 20 41 44 44 20 48 4b 45 59 5f 90 02 10 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 90 00 } //10
		$a_00_4 = {6f 70 65 6e 3d 52 45 43 59 43 4c 45 52 5c 61 75 74 6f 70 6c 61 79 2e 65 78 65 } //1 open=RECYCLER\autoplay.exe
		$a_00_5 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 52 45 43 59 43 4c 45 52 5c 61 75 74 6f 70 6c 61 79 2e 65 78 65 } //1 shell\open\Command=RECYCLER\autoplay.exe
		$a_00_6 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 43 6f 6d 6d 61 6e 64 3d 52 45 43 59 43 4c 45 52 5c 61 75 74 6f 70 6c 61 79 2e 65 78 65 } //1 shell\explore\Command=RECYCLER\autoplay.exe
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_02_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=41
 
}