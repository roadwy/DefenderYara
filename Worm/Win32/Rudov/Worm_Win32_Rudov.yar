
rule Worm_Win32_Rudov{
	meta:
		description = "Worm:Win32/Rudov,SIGNATURE_TYPE_PEHSTR,40 00 3f 00 0b 00 00 "
		
	strings :
		$a_01_0 = {46 61 73 74 4d 4d 20 42 6f 72 6c 61 6e 64 20 45 64 69 74 69 6f 6e 20 } //10 FastMM Borland Edition 
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //10 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {41 6e 74 69 44 75 72 6f 76 } //10 AntiDurov
		$a_01_3 = {44 75 72 6f 76 20 56 4b 6f 6e 74 61 6b 74 65 20 53 65 72 76 69 63 65 } //10 Durov VKontakte Service
		$a_01_4 = {57 53 41 41 73 79 6e 63 53 65 6c 65 63 74 } //10 WSAAsyncSelect
		$a_01_5 = {68 74 74 70 3a 2f 2f 76 6b 6f 6e 74 61 6b 74 65 2e 72 75 } //10 http://vkontakte.ru
		$a_01_6 = {41 63 63 65 70 74 2d 43 68 61 72 73 65 74 3a 20 49 53 4f 2d 38 38 35 39 2d 31 2c 75 74 66 2d 38 3b 71 3d 30 2e 37 2c 2a 3b 71 3d 30 2e 37 } //1 Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7
		$a_01_7 = {2f 6d 61 69 6c 2e 70 68 70 3f 61 63 74 3d 77 72 69 74 65 26 74 6f 3d } //1 /mail.php?act=write&to=
		$a_01_8 = {3c 69 6e 70 75 74 20 74 79 70 65 3d 22 68 69 64 64 65 6e 22 20 69 64 3d 22 74 6f 5f 72 65 70 6c 79 22 20 6e 61 6d 65 3d 22 74 6f 5f 72 65 70 6c 79 22 20 76 61 6c 75 65 3d 22 } //1 <input type="hidden" id="to_reply" name="to_reply" value="
		$a_01_9 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 6f 6f 6b 69 65 73 } //1 \Microsoft\Windows\Cookies
		$a_01_10 = {2d 6b 69 6c 6c } //1 -kill
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=63
 
}