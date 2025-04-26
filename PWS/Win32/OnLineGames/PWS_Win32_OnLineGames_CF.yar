
rule PWS_Win32_OnLineGames_CF{
	meta:
		description = "PWS:Win32/OnLineGames.CF,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 75 73 65 72 3d 25 73 26 73 70 61 73 73 3d 25 73 26 73 65 72 69 61 6c 3d 25 73 26 73 65 72 4e 75 6d 3d 25 73 26 6c 65 76 65 6c 3d 25 64 26 6d 6f 6e 65 79 3d 25 64 26 6c 69 6e 65 3d 25 73 } //1 suser=%s&spass=%s&serial=%s&serNum=%s&level=%d&money=%d&line=%s
		$a_00_1 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //1 Accept-Language: zh-cn
		$a_02_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c [0-10] 2e 73 79 73 } //1
		$a_00_3 = {52 65 66 65 72 65 72 3a 20 6d 61 6b 65 73 75 72 65 74 68 69 73 6d 79 6d 61 69 6c } //1 Referer: makesurethismymail
		$a_00_4 = {54 65 6e 51 51 41 63 63 6f 75 6e 74 2e 64 6c 6c } //1 TenQQAccount.dll
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}