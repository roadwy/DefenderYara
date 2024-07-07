
rule PWS_Win32_OnLineGames_AG{
	meta:
		description = "PWS:Win32/OnLineGames.AG,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {2f 6e 65 77 2f 67 65 74 2e 61 73 70 } //1 /new/get.asp
		$a_01_1 = {6c 6f 67 69 6e 5f 70 61 73 73 77 6f 72 64 } //1 login_password
		$a_01_2 = {6c 6f 67 69 6e 5f 65 6d 61 69 6c } //1 login_email
		$a_01_3 = {2e 70 61 79 70 61 6c 2e } //1 .paypal.
		$a_01_4 = {6f 6e 6c 69 6e 65 67 61 6d 65 } //1 onlinegame
		$a_01_5 = {25 73 3f 75 73 3d 25 73 26 70 73 3d 25 73 26 6d 6f 3d 25 73 } //1 %s?us=%s&ps=%s&mo=%s
		$a_01_6 = {63 61 72 64 6c 65 65 } //1 cardlee
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}