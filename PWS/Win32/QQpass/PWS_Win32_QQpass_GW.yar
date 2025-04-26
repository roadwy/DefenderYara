
rule PWS_Win32_QQpass_GW{
	meta:
		description = "PWS:Win32/QQpass.GW,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 74 65 70 6e 75 6d 3d 25 64 26 75 69 64 3d 25 73 26 63 6d 64 3d 4f 50 45 4e 5f 55 52 4c } //1 stepnum=%d&uid=%s&cmd=OPEN_URL
		$a_01_1 = {73 74 65 70 6e 75 6d 3d 25 64 26 75 69 64 3d 25 73 26 63 6d 64 3d 4c 6f 67 69 6e 51 51 } //1 stepnum=%d&uid=%s&cmd=LoginQQ
		$a_01_2 = {50 4f 53 54 20 2f 61 70 69 2e 70 68 70 3f 6d 6f 64 3d 79 7a 6d 26 61 63 74 3d 73 74 61 74 65 20 48 54 54 50 2f 31 2e 31 } //1 POST /api.php?mod=yzm&act=state HTTP/1.1
		$a_01_3 = {66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 75 73 65 72 5f 70 77 22 } //1 form-data; name="user_pw"
		$a_01_4 = {66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 75 73 65 72 5f 6e 61 6d 65 22 } //1 form-data; name="user_name"
		$a_01_5 = {2f 75 70 64 61 74 65 31 2e 70 68 70 3f 71 71 74 79 70 65 3d 25 64 26 73 74 61 74 75 73 3d 31 26 75 69 64 3d 25 73 } //1 /update1.php?qqtype=%d&status=1&uid=%s
		$a_01_6 = {43 3a 5c 39 32 42 39 45 4e 31 53 2e 74 78 74 } //1 C:\92B9EN1S.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}