
rule Trojan_Win32_Bladabindi_J_ibt{
	meta:
		description = "Trojan:Win32/Bladabindi.J!ibt,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 65 79 6c 6f 67 67 65 72 } //1 Keylogger
		$a_01_1 = {6b 65 79 53 74 72 6f 6b 65 73 4c 6f 67 } //1 keyStrokesLog
		$a_01_2 = {76 69 63 74 69 6d 73 4f 77 6e 65 72 } //1 victimsOwner
		$a_01_3 = {2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 30 00 20 00 2d 00 6e 00 20 00 32 00 20 00 26 00 20 00 64 00 65 00 6c 00 20 00 22 00 } //1 /c ping 0 -n 2 & del "
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}