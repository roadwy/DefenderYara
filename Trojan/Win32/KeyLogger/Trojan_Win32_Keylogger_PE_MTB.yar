
rule Trojan_Win32_Keylogger_PE_MTB{
	meta:
		description = "Trojan:Win32/Keylogger.PE!MTB,SIGNATURE_TYPE_PEHSTR,11 00 11 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4b 65 79 6c 6f 67 67 65 72 } //05 00 
		$a_01_1 = {64 00 6f 00 6e 00 6b 00 65 00 79 00 62 00 61 00 6c 00 6c 00 73 00 } //01 00 
		$a_01_2 = {73 00 6d 00 74 00 70 00 2e 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //01 00 
		$a_01_3 = {4d 61 69 6c 41 64 64 72 65 73 73 43 6f 6c 6c 65 63 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}