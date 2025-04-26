
rule Trojan_Win32_Fordel_A{
	meta:
		description = "Trojan:Win32/Fordel.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {40 64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 65 3a 5c 2a 2e 2a 0d 0a 40 64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 64 3a 5c 2a 2e 2a } //1
		$a_01_1 = {40 64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 7a 3a 5c 2a 2e 2a } //1 @del /f /s /q z:\*.*
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}