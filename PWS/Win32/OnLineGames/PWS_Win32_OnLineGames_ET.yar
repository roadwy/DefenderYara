
rule PWS_Win32_OnLineGames_ET{
	meta:
		description = "PWS:Win32/OnLineGames.ET,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {c6 04 03 e9 40 8b ca c1 e9 00 80 e1 ff 88 0c 03 } //2
		$a_01_1 = {61 63 74 69 6f 6e 3d } //2 action=
		$a_01_2 = {26 7a 74 3d } //2 &zt=
		$a_01_3 = {50 61 74 63 68 44 4c 4c 2e 64 6c 6c 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=6
 
}