
rule Worm_Win32_Silly_P2P_G{
	meta:
		description = "Worm:Win32/Silly_P2P.G,SIGNATURE_TYPE_PEHSTR_EXT,2b 00 2b 00 0a 00 00 "
		
	strings :
		$a_02_0 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 3d [0-20] 2e 65 78 65 } //10
		$a_02_1 = {69 63 6f 6e 3d 25 [0-10] 25 5c 73 79 73 74 65 6d 33 32 5c 53 48 45 4c 4c 33 32 2e 64 6c 6c 2c } //10
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //10 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_00_3 = {5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //10 \autorun.inf
		$a_00_4 = {53 6f 66 74 77 61 72 65 5c 42 65 61 72 53 68 61 72 65 5c 47 65 6e 65 72 61 6c } //1 Software\BearShare\General
		$a_00_5 = {53 6f 66 74 77 61 72 65 5c 69 4d 65 73 68 5c 47 65 6e 65 72 61 6c } //1 Software\iMesh\General
		$a_00_6 = {53 6f 66 74 77 61 72 65 5c 53 68 61 72 65 61 7a 61 5c } //1 Software\Shareaza\
		$a_00_7 = {53 6f 66 74 77 61 72 65 5c 4b 61 7a 61 61 5c } //1 Software\Kazaa\
		$a_00_8 = {53 6f 66 74 77 61 72 65 5c 44 43 2b 2b } //1 Software\DC++
		$a_00_9 = {53 6f 66 74 77 61 72 65 5c 65 4d 75 6c 65 } //1 Software\eMule
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=43
 
}