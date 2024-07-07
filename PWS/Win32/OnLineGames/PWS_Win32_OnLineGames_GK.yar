
rule PWS_Win32_OnLineGames_GK{
	meta:
		description = "PWS:Win32/OnLineGames.GK,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 2a 00 09 00 00 "
		
	strings :
		$a_00_0 = {6b 69 63 6b 2e 61 73 68 78 3f 75 73 65 72 6e 61 6d 65 3d } //10 kick.ashx?username=
		$a_00_1 = {62 61 6e 6b 70 61 73 73 77 6f 72 64 2e 61 73 70 78 3f 75 73 65 72 6e 61 6d 65 3d } //10 bankpassword.aspx?username=
		$a_00_2 = {63 61 73 68 2e 61 73 70 78 3f 75 73 65 72 6e 61 6d 65 3d } //10 cash.aspx?username=
		$a_00_3 = {79 75 61 6e 62 61 6f 2e 61 73 70 78 3f 75 73 65 72 6e 61 6d 65 3d } //10 yuanbao.aspx?username=
		$a_00_4 = {6d 69 62 61 6f 70 69 63 74 75 72 65 2e 61 73 70 78 3f 75 73 65 72 6e 61 6d 65 3d } //10 mibaopicture.aspx?username=
		$a_00_5 = {6d 69 62 61 6f 2e 61 73 70 78 3f 75 73 65 72 6e 61 6d 65 3d } //10 mibao.aspx?username=
		$a_01_6 = {4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65 20 50 69 63 74 75 72 65 20 4d 61 6e 61 67 65 72 } //1 Microsoft Office Picture Manager
		$a_01_7 = {4d 69 63 72 6f 73 6f 66 74 20 50 68 6f 74 6f 20 45 64 69 74 6f 72 } //1 Microsoft Photo Editor
		$a_01_8 = {49 72 66 61 6e 56 69 65 77 } //1 IrfanView
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=42
 
}