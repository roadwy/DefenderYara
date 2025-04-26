
rule Backdoor_Win32_Phdet_G{
	meta:
		description = "Backdoor:Win32/Phdet.G,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 20 73 65 72 76 69 63 65 20 64 6f 77 6e 6c 6f 61 64 69 6e 67 20 61 6e 64 20 69 6e 73 74 61 6c 6c 69 6e 67 20 57 69 6e 64 6f 77 73 20 73 65 63 75 72 69 74 79 20 75 70 64 61 74 65 73 } //1 This service downloading and installing Windows security updates
		$a_01_1 = {47 45 54 20 68 74 74 70 3a 2f 2f 79 61 68 6f 6f 2e 63 6f 6d } //1 GET http://yahoo.com
		$a_01_2 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //1 application/x-www-form-urlencoded
		$a_01_3 = {76 3d 25 73 26 69 64 3d 25 73 26 73 6f 63 6b 73 3d 25 64 26 68 74 74 70 3d 25 64 26 70 69 6e 67 3d 25 64 26 73 70 65 65 64 3d 25 64 } //1 v=%s&id=%s&socks=%d&http=%d&ping=%d&speed=%d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}