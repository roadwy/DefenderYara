
rule Worm_Win32_Ganelp_AF_MTB{
	meta:
		description = "Worm:Win32/Ganelp.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {6d 73 67 5f 62 61 6e 6b 6d 6f 6e 65 79 } //msg_bankmoney  3
		$a_80_1 = {53 65 74 50 72 6f 78 79 43 72 65 64 65 6e 74 69 61 6c 73 } //SetProxyCredentials  3
		$a_80_2 = {5c 41 64 5c 63 6f 6e 66 69 67 2e 69 6e 69 } //\Ad\config.ini  3
		$a_80_3 = {61 63 74 69 6f 6e 74 6f 3d 73 68 6f 77 6d 6f 6e 65 79 26 61 72 65 61 69 64 3d 75 6e 64 65 66 69 6e 65 64 26 67 61 6d 65 69 64 3d } //actionto=showmoney&areaid=undefined&gameid=  3
		$a_80_4 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 } //BlackMoon RunTime  3
		$a_80_5 = {42 4f 47 59 27 53 20 47 41 4d 45 } //BOGY'S GAME  3
		$a_80_6 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 66 72 69 65 6e 64 6c 2e 64 6c 6c } //c:\windows\friendl.dll  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}