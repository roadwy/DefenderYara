
rule PWS_Win32_Frethog_BN{
	meta:
		description = "PWS:Win32/Frethog.BN,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {3f 61 63 74 3d 67 65 74 6f 76 65 72 26 61 63 63 6f 75 6e 74 3d } //1 ?act=getover&account=
		$a_01_1 = {65 6c 65 6d 65 6e 74 63 6c 69 65 6e 74 2e 65 78 65 } //1 elementclient.exe
		$a_01_2 = {5c 44 61 74 61 5c 69 64 2e 69 6e 69 } //1 \Data\id.ini
		$a_01_3 = {3f 61 63 74 3d 67 65 74 70 6f 73 26 61 63 63 6f 75 6e 74 3d 25 73 } //1 ?act=getpos&account=%s
		$a_01_4 = {73 65 72 76 65 72 3d 25 73 26 61 63 63 6f 75 6e 74 3d 25 73 26 70 61 73 73 77 6f 72 64 31 3d 25 73 26 50 72 6f 74 50 61 73 73 3d 25 73 26 56 65 72 69 66 79 3d 25 73 } //1 server=%s&account=%s&password1=%s&ProtPass=%s&Verify=%s
		$a_01_5 = {25 73 3f 73 3d 25 73 } //1 %s?s=%s
		$a_01_6 = {3f 61 63 74 3d 67 65 74 74 68 6d 62 6f 6b 26 61 63 63 6f 75 6e 74 3d } //1 ?act=getthmbok&account=
		$a_01_7 = {5c 75 73 65 72 64 61 74 61 5c 63 75 72 72 65 6e 74 73 65 72 76 65 72 2e 69 6e 69 } //1 \userdata\currentserver.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}