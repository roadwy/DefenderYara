
rule Spammer_Win32_Fifesock_A{
	meta:
		description = "Spammer:Win32/Fifesock.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 09 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 66 62 5f 73 70 61 6d 5c 66 62 5f 73 70 61 6d 5c 52 65 6c 65 61 73 65 5c 66 62 5f 73 70 61 6d 2e 70 64 62 } //2 C:\fb_spam\fb_spam\Release\fb_spam.pdb
		$a_01_1 = {73 65 63 75 72 69 74 79 5f 74 6f 6b 65 6e 3d 25 73 26 72 65 71 49 64 3d 26 62 6c 6f 67 49 44 3d 26 68 63 61 3d 74 72 75 65 26 62 6c 6f 67 74 69 74 6c 65 3d 25 73 26 62 6c 6f 67 73 70 6f 74 6e 61 6d 65 3d 25 73 26 6f 6b 3d 4e 65 78 74 } //1 security_token=%s&reqId=&blogID=&hca=true&blogtitle=%s&blogspotname=%s&ok=Next
		$a_01_2 = {6f 6f 67 6c 65 2e 63 6f 6d 2f 61 63 63 6f 75 6e 74 73 2f 53 65 72 76 69 63 65 4c 6f 67 69 6e 3f 73 65 72 76 69 63 65 3d 62 6c 6f 67 67 65 72 26 63 6f 6e 74 69 6e 75 65 3d 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 6c 6f 67 67 65 72 2e 63 6f 6d 2f 6c 6f 67 69 6e 7a 3f } //1 oogle.com/accounts/ServiceLogin?service=blogger&continue=https://www.blogger.com/loginz?
		$a_01_3 = {25 73 3f 61 63 74 3d 66 62 5f 65 78 74 65 6e 64 65 64 26 75 73 65 72 3d 25 73 26 70 61 73 73 3d 25 73 26 6e 75 6d 3d 30 26 74 6f 74 61 6c 3d 25 73 26 64 6f 62 3d 25 73 26 73 74 61 74 75 73 3d 73 70 61 6d } //2 %s?act=fb_extended&user=%s&pass=%s&num=0&total=%s&dob=%s&status=spam
		$a_01_4 = {75 73 65 72 6e 61 6d 65 3d 25 73 26 70 61 73 73 77 6f 72 64 3d 25 73 26 61 75 74 68 65 6e 74 69 63 69 74 79 5f 74 6f 6b 65 6e 3d 25 73 } //1 username=%s&password=%s&authenticity_token=%s
		$a_01_5 = {3f 65 64 69 74 3d 62 69 72 74 68 64 61 79 } //1 ?edit=birthday
		$a_01_6 = {5c 5c 2e 5c 70 69 70 65 5c 74 77 69 74 74 65 72 } //1 \\.\pipe\twitter
		$a_01_7 = {5c 5c 2e 5c 70 69 70 65 5c 62 6c 6f 67 73 70 6f 74 } //1 \\.\pipe\blogspot
		$a_01_8 = {5c 5c 2e 5c 70 69 70 65 5c 66 61 63 65 62 6f 6f 6b } //1 \\.\pipe\facebook
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=4
 
}