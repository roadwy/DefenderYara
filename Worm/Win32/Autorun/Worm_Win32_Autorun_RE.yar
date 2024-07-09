
rule Worm_Win32_Autorun_RE{
	meta:
		description = "Worm:Win32/Autorun.RE,SIGNATURE_TYPE_PEHSTR_EXT,2b 00 2a 00 07 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c } //10 SOFTWARE\Borland\Delphi\
		$a_00_1 = {61 75 74 6f 72 75 6e 2e 69 6e 66 00 } //10
		$a_00_2 = {5b 61 75 74 6f 72 75 6e 5d 00 } //10 慛瑵牯湵]
		$a_02_3 = {52 45 47 20 41 44 44 20 48 4b 45 59 5f [0-10] 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 20 } //10
		$a_00_4 = {6f 70 65 6e 3d 52 45 43 59 43 4c 45 52 5c } //1 open=RECYCLER\
		$a_00_5 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 52 45 43 59 43 4c 45 52 5c } //1 shell\open\Command=RECYCLER\
		$a_00_6 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 43 6f 6d 6d 61 6e 64 3d 52 45 43 59 43 4c 45 52 5c } //1 shell\explore\Command=RECYCLER\
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_02_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=42
 
}