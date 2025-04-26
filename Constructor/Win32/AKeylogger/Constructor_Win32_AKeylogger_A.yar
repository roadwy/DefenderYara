
rule Constructor_Win32_AKeylogger_A{
	meta:
		description = "Constructor:Win32/AKeylogger.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 6c 62 65 72 74 69 6e 6f 20 4b 65 79 6c 6f 67 67 65 72 20 43 72 65 61 74 6f 72 } //1 Albertino Keylogger Creator
		$a_01_1 = {70 00 6c 00 65 00 61 00 73 00 65 00 20 00 6d 00 61 00 6b 00 65 00 20 00 73 00 75 00 72 00 65 00 20 00 79 00 6f 00 75 00 72 00 20 00 46 00 54 00 50 00 20 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 20 00 61 00 72 00 65 00 20 00 63 00 6f 00 72 00 72 00 65 00 63 00 74 00 21 00 21 00 21 00 } //1 please make sure your FTP settings are correct!!!
		$a_01_2 = {3f 00 63 00 6d 00 64 00 3d 00 5f 00 73 00 2d 00 78 00 63 00 6c 00 69 00 63 00 6b 00 26 00 68 00 6f 00 73 00 74 00 65 00 64 00 5f 00 62 00 75 00 74 00 74 00 6f 00 6e 00 5f 00 69 00 64 00 3d 00 31 00 35 00 33 00 36 00 32 00 33 00 36 00 } //1 ?cmd=_s-xclick&hosted_button_id=1536236
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}