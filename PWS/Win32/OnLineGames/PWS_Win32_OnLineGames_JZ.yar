
rule PWS_Win32_OnLineGames_JZ{
	meta:
		description = "PWS:Win32/OnLineGames.JZ,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {5c 78 6c 65 6c 73 70 } //1 \xlelsp
		$a_01_1 = {5c 62 76 6c 72 64 77 2e 65 78 65 } //1 \bvlrdw.exe
		$a_01_2 = {5c 73 74 61 72 74 5c 55 73 65 72 53 65 74 74 69 6e 67 2e 69 6e 69 } //1 \start\UserSetting.ini
		$a_01_3 = {5c 61 6f 77 6a 66 6b 2e 65 78 65 } //1 \aowjfk.exe
		$a_01_4 = {5c 71 71 6c 6f 67 69 6e 2e 65 78 65 } //1 \qqlogin.exe
		$a_01_5 = {5c 64 6e 66 63 68 69 6e 61 2e 65 78 65 } //1 \dnfchina.exe
		$a_01_6 = {5c 64 6e 66 2e 65 78 65 } //1 \dnf.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}