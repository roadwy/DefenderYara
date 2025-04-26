
rule Trojan_Win32_TrickBot_X{
	meta:
		description = "Trojan:Win32/TrickBot.X,SIGNATURE_TYPE_PEHSTR,05 00 05 00 0d 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 70 72 6f 63 6c 69 73 74 22 } //2 Content-Disposition: form-data; name="proclist"
		$a_01_1 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 73 79 73 69 6e 66 6f 22 } //2 Content-Disposition: form-data; name="sysinfo"
		$a_01_2 = {2a 2a 2a 50 52 4f 43 45 53 53 20 4c 49 53 54 2a 2a 2a } //1 ***PROCESS LIST***
		$a_01_3 = {44 70 6f 73 74 20 73 65 72 76 65 72 73 20 75 6e 61 76 61 69 6c 61 62 6c 65 } //4 Dpost servers unavailable
		$a_01_4 = {73 65 6e 74 20 50 41 53 53 57 4f 52 44 53 20 74 6f 20 44 50 6f 73 74 20 73 65 72 76 65 72 } //4 sent PASSWORDS to DPost server
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 42 4c 42 65 61 63 6f 6e } //1 Software\Google\Chrome\BLBeacon
		$a_01_6 = {73 00 62 00 6f 00 78 00 5f 00 61 00 6c 00 74 00 65 00 72 00 6e 00 61 00 74 00 65 00 5f 00 64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 } //1 sbox_alternate_desktop
		$a_01_7 = {77 65 62 69 6e 6a 65 63 74 33 32 2e 70 64 62 } //3 webinject32.pdb
		$a_01_8 = {63 6f 6e 66 20 63 74 6c 3d 22 53 65 74 43 6f 6e 66 22 20 66 69 6c 65 3d 22 64 70 6f 73 74 22 20 70 65 72 69 6f 64 3d 22 } //2 conf ctl="SetConf" file="dpost" period="
		$a_01_9 = {63 6f 6e 66 20 63 74 6c 3d 22 64 70 6f 73 74 22 20 66 69 6c 65 3d 22 64 70 6f 73 74 22 20 70 65 72 69 6f 64 3d 22 } //2 conf ctl="dpost" file="dpost" period="
		$a_01_10 = {45 53 54 52 5f 50 41 53 53 5f } //2 ESTR_PASS_
		$a_01_11 = {5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 2e 62 61 6b } //1 \User Data\Default\Login Data.bak
		$a_01_12 = {47 72 61 62 5f 50 61 73 73 77 6f 72 64 73 5f 43 68 72 6f 6d 65 28 29 20 73 75 63 63 65 73 73 } //1 Grab_Passwords_Chrome() success
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*3+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=5
 
}