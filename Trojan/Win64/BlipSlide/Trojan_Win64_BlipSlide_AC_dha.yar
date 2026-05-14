
rule Trojan_Win64_BlipSlide_AC_dha{
	meta:
		description = "Trojan:Win64/BlipSlide.AC!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 77 72 73 68 6c 49 6e 76 6f 6b 65 72 } //1 PwrshlInvoker
		$a_01_1 = {57 69 6e 48 74 74 70 57 72 61 70 70 65 72 } //1 WinHttpWrapper
		$a_01_2 = {65 78 65 63 75 74 65 5f 63 6f 6d 6d 61 6e 64 } //1 execute_command
		$a_01_3 = {51 45 41 55 43 6f 6d 6d 61 6e 64 } //1 QEAUCommand
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}