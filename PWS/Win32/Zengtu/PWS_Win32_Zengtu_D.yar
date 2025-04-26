
rule PWS_Win32_Zengtu_D{
	meta:
		description = "PWS:Win32/Zengtu.D,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {7a 68 65 6e 67 74 75 } //1 zhengtu
		$a_01_1 = {73 65 72 76 65 72 6e 61 6d 65 } //1 servername
		$a_01_2 = {63 6f 6e 66 69 67 2e 69 6e 69 } //1 config.ini
		$a_01_3 = {43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a 20 25 6c 64 } //1 Content-Length: %ld
		$a_01_4 = {25 64 2e 25 64 2e 25 64 2e 25 64 3b } //1 %d.%d.%d.%d;
		$a_01_5 = {57 69 6e 39 35 4f 53 52 32 } //1 Win95OSR2
		$a_01_6 = {69 6d 61 67 65 2f 70 6a 70 65 67 2c 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 76 6e 64 2e 6d 73 2d 65 78 63 65 6c 2c } //1 image/pjpeg, application/vnd.ms-excel,
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}