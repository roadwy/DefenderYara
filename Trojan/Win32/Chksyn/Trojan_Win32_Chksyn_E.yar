
rule Trojan_Win32_Chksyn_E{
	meta:
		description = "Trojan:Win32/Chksyn.E,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {76 3d 25 64 26 73 3d 25 64 26 68 3d 25 64 26 75 6e 3d 25 73 26 66 74 70 3d 25 73 26 6f 3d 25 64 26 63 3d 25 64 26 69 70 3d 25 73 26 73 79 73 3d 25 73 26 75 69 64 3d 25 64 26 77 3d 25 64 } //1 v=%d&s=%d&h=%d&un=%s&ftp=%s&o=%d&c=%d&ip=%s&sys=%s&uid=%d&w=%d
		$a_01_1 = {2e 65 78 65 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 70 72 6f 67 72 61 6d 20 3d 20 } //1 .exe firewall add allowedprogram program = 
		$a_01_2 = {4c 00 6f 00 61 00 64 00 41 00 70 00 70 00 49 00 6e 00 69 00 74 00 5f 00 44 00 4c 00 4c 00 73 00 } //1 LoadAppInit_DLLs
		$a_01_3 = {4d 61 63 72 6f 6d 65 64 69 61 5c 53 77 55 70 64 61 74 65 5c } //1 Macromedia\SwUpdate\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}