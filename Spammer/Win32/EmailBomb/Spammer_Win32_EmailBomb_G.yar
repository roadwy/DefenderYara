
rule Spammer_Win32_EmailBomb_G{
	meta:
		description = "Spammer:Win32/EmailBomb.G,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 69 67 6e 55 70 2e 44 6f 50 6f 73 74 28 29 3b } //1 SignUp.DoPost();
		$a_01_1 = {2f 61 63 63 6f 75 6e 74 5f 70 6f 73 74 2e 61 73 70 } //1 /account_post.asp
		$a_01_2 = {25 73 3f 74 79 70 65 3d 25 73 26 73 79 73 74 65 6d 3d 25 73 26 69 64 3d 25 73 26 73 74 61 74 75 73 3d 25 73 26 6e 3d 25 64 26 65 78 74 72 61 3d 25 73 } //2 %s?type=%s&system=%s&id=%s&status=%s&n=%d&extra=%s
		$a_01_3 = {25 41 50 50 44 41 54 41 25 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 63 63 73 72 } //2 %APPDATA%\Microsoft\Internet Explorer\ccsr
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=4
 
}