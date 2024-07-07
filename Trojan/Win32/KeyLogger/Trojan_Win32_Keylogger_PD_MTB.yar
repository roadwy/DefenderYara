
rule Trojan_Win32_Keylogger_PD_MTB{
	meta:
		description = "Trojan:Win32/Keylogger.PD!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 00 6d 00 74 00 70 00 2e 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //1 smtp.gmail.com
		$a_01_1 = {4b 00 45 00 59 00 4c 00 4f 00 47 00 20 00 42 00 4f 00 49 00 5a 00 5a 00 } //1 KEYLOG BOIZZ
		$a_01_2 = {43 00 3a 00 2f 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 2f 00 6d 00 79 00 6c 00 6f 00 67 00 2e 00 74 00 78 00 74 00 } //1 C:/ProgramData/mylog.txt
		$a_01_3 = {46 69 6e 61 6c 4b 65 79 4c 6f 67 67 65 72 } //1 FinalKeyLogger
		$a_01_4 = {4d 61 69 6c 41 64 64 72 65 73 73 43 6f 6c 6c 65 63 74 69 6f 6e } //1 MailAddressCollection
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}