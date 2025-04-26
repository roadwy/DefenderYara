
rule Trojan_Win32_Licat_A{
	meta:
		description = "Trojan:Win32/Licat.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 53 50 52 4f 54 45 43 54 20 55 4e 50 41 43 4b 45 44 20 42 59 20 41 56 50 } //1 ASPROTECT UNPACKED BY AVP
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 65 73 73 65 6e 67 65 72 5c 6d 73 6d 73 67 73 2e 65 78 65 5c 33 } //1 C:\Program Files\Messenger\msmsgs.exe\3
		$a_01_2 = {33 00 33 00 33 00 78 00 78 00 78 00 78 00 73 00 73 00 73 00 78 00 78 00 78 00 78 00 78 00 33 00 67 00 67 00 33 00 33 00 33 00 33 00 33 00 33 00 33 00 } //1 333xxxxsssxxxxx3gg3333333
		$a_01_3 = {66 00 75 00 6e 00 70 00 69 00 63 00 2e 00 6f 00 72 00 67 00 2f 00 } //1 funpic.org/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}