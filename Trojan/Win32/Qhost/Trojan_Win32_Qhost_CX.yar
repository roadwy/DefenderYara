
rule Trojan_Win32_Qhost_CX{
	meta:
		description = "Trojan:Win32/Qhost.CX,SIGNATURE_TYPE_PEHSTR_EXT,08 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 63 68 6f 20 73 74 61 72 74 20 53 68 6f 77 53 79 73 74 65 6d 49 6d 61 67 65 2e 65 78 65 20 3e 3e 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 66 64 73 66 73 64 66 77 2e 63 6d 64 } //2 echo start ShowSystemImage.exe >> %systemroot%\fdsfsdfw.cmd
		$a_01_1 = {65 63 68 6f 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 63 6d 64 2e 65 78 65 20 3e 3e 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 66 65 65 65 66 2e 63 6d 64 } //2 echo taskkill /im cmd.exe >> %systemroot%\feeef.cmd
		$a_01_2 = {65 63 68 6f 20 31 38 34 2e 38 32 2e 34 33 2e 32 30 36 20 77 77 77 2e 6f 64 6e 6f 6b 6c 61 73 73 6e 69 6b 69 2e 72 75 20 3e 3e 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //3 echo 184.82.43.206 www.odnoklassniki.ru >> %systemroot%\system32\drivers\etc\hosts
		$a_01_3 = {65 63 68 6f 20 64 65 6c 20 2f 66 20 2f 71 20 2a 2e 73 63 72 20 3e 3e 20 20 7e 72 65 73 75 6c 74 2e 63 6d 64 } //1 echo del /f /q *.scr >>  ~result.cmd
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1) >=4
 
}