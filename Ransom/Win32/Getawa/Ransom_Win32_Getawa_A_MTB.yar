
rule Ransom_Win32_Getawa_A_MTB{
	meta:
		description = "Ransom:Win32/Getawa.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {6d 64 20 25 77 69 6e 64 69 72 25 5c 53 79 73 57 4f 57 36 34 5c 6a 61 76 61 5c 6a 61 77 61 } //1 md %windir%\SysWOW64\java\jawa
		$a_02_1 = {70 69 6e 67 20 2d 6e 20 31 20 90 02 03 2e 90 02 03 2e 90 02 03 2e 90 02 03 20 7c 20 66 69 6e 64 20 22 54 54 4c 3d 22 20 3e 6e 75 6c 90 00 } //1
		$a_00_2 = {67 65 74 72 61 72 74 69 6d 65 2e 62 61 74 } //1 getrartime.bat
		$a_00_3 = {67 65 74 72 61 72 74 69 6d 65 2e 65 78 65 } //1 getrartime.exe
		$a_00_4 = {63 6f 70 79 20 77 72 2d 33 2e 2d 37 31 2e 7a 69 70 20 77 72 2d 33 2e 2d 37 31 2e 65 78 65 } //1 copy wr-3.-71.zip wr-3.-71.exe
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}