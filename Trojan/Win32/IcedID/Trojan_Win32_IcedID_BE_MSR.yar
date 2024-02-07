
rule Trojan_Win32_IcedID_BE_MSR{
	meta:
		description = "Trojan:Win32/IcedID.BE!MSR,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {45 54 50 43 41 6e 57 72 42 63 69 } //02 00  ETPCAnWrBci
		$a_01_1 = {49 50 77 55 41 51 49 78 59 4a 63 43 6a } //02 00  IPwUAQIxYJcCj
		$a_01_2 = {49 6b 48 68 75 44 65 79 4a 4f 4c 64 7a 63 } //02 00  IkHhuDeyJOLdzc
		$a_01_3 = {51 7a 4d 51 45 44 44 6c 6f 54 76 6d 72 } //02 00  QzMQEDDloTvmr
		$a_01_4 = {56 45 4a 6a 45 5a 65 49 57 71 44 43 5a } //02 00  VEJjEZeIWqDCZ
		$a_01_5 = {58 43 59 68 62 76 4c 79 65 43 4c 57 } //02 00  XCYhbvLyeCLW
		$a_01_6 = {58 46 48 4f 4f 50 63 45 4b 51 6c 46 } //02 00  XFHOOPcEKQlF
		$a_01_7 = {59 44 73 6c 55 48 68 4e 4f 4e 6b 4d 52 55 } //00 00  YDslUHhNONkMRU
	condition:
		any of ($a_*)
 
}