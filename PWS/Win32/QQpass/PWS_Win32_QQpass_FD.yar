
rule PWS_Win32_QQpass_FD{
	meta:
		description = "PWS:Win32/QQpass.FD,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 74 65 6e 2d 63 65 6e 74 2e 79 73 31 36 38 2e 63 6f 6d } //03 00  http://ten-cent.ys168.com
		$a_01_1 = {65 78 65 66 69 6c 65 73 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 5c } //01 00  exefiles\shell\open\command\
		$a_01_2 = {5b 53 59 53 52 51 5d } //02 00  [SYSRQ]
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 6f 71 6f 2e 74 6b } //00 00  http://www.soqo.tk
	condition:
		any of ($a_*)
 
}