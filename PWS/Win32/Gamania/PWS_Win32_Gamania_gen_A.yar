
rule PWS_Win32_Gamania_gen_A{
	meta:
		description = "PWS:Win32/Gamania.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,12 00 10 00 0a 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //2 CreateToolhelp32Snapshot
		$a_00_1 = {26 73 75 62 6a 65 63 74 3d } //2 &subject=
		$a_00_2 = {26 73 65 6e 64 65 72 3d } //2 &sender=
		$a_00_3 = {63 67 69 2d 62 69 6e 2f 6c 6f 67 69 6e 2e 63 67 69 3f 73 72 76 3d } //2 cgi-bin/login.cgi?srv=
		$a_00_4 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //2 Accept-Language: zh-cn
		$a_01_5 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //2 SetWindowsHookExA
		$a_00_6 = {47 61 6d 61 47 6f 6f 64 4c 6f 63 6b 2e 61 73 70 78 } //2 GamaGoodLock.aspx
		$a_00_7 = {2e 67 61 6d 61 6e 69 61 2e 63 6f 6d 2f } //2 .gamania.com/
		$a_00_8 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 } //2 Internet Explorer_Server
		$a_00_9 = {49 48 54 4d 4c 45 6c 65 6d 65 6e 74 43 6f 6c 6c 65 63 74 69 6f 6e } //1 IHTMLElementCollection
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_01_5  & 1)*2+(#a_00_6  & 1)*2+(#a_00_7  & 1)*2+(#a_00_8  & 1)*2+(#a_00_9  & 1)*1) >=16
 
}