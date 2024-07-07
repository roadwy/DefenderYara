
rule PWS_Win32_OnLineGames_BI{
	meta:
		description = "PWS:Win32/OnLineGames.BI,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 65 72 76 65 72 3d 25 73 26 61 63 63 6f 75 6e 74 3d 25 73 26 70 61 73 73 77 6f 72 64 31 3d 25 73 } //1 server=%s&account=%s&password1=%s
		$a_00_1 = {26 6c 65 76 65 6c 73 3d 25 73 26 63 61 73 68 3d 25 73 26 6e 61 6d 65 3d 25 73 26 73 70 65 63 69 61 6c 53 69 67 6e 3d 25 73 26 } //1 &levels=%s&cash=%s&name=%s&specialSign=%s&
		$a_00_2 = {26 50 72 6f 74 50 61 73 73 3d 25 73 26 56 65 72 69 66 79 3d 25 73 } //1 &ProtPass=%s&Verify=%s
		$a_02_3 = {68 74 74 70 3a 2f 2f 90 02 20 2f 70 6f 73 74 2e 61 73 70 90 00 } //1
		$a_00_4 = {3f 61 63 74 3d 67 65 74 70 6f 73 26 61 63 63 6f 75 6e 74 3d 25 73 } //1 ?act=getpos&account=%s
		$a_00_5 = {5c 75 73 65 72 64 61 74 61 5c 63 75 72 72 65 6e 74 73 65 72 76 65 72 2e 69 6e 69 } //1 \userdata\currentserver.ini
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}