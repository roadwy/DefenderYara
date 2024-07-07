
rule Trojan_Win32_Keylogger_PF_MTB{
	meta:
		description = "Trojan:Win32/Keylogger.PF!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 6b 00 6c 00 6f 00 67 00 73 00 2e 00 74 00 78 00 74 00 } //1 :\windows\klogs.txt
		$a_01_1 = {4c 00 6f 00 67 00 20 00 53 00 65 00 6e 00 74 00 20 00 62 00 79 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //1 Log Sent by Keylogger
		$a_01_2 = {6e 00 65 00 77 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 73 00 } //1 newKeylogs
		$a_01_3 = {73 00 6d 00 74 00 70 00 2e 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //1 smtp.gmail.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}