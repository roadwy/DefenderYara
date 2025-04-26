
rule Trojan_Win32_SourLogger_A_dha{
	meta:
		description = "Trojan:Win32/SourLogger.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {35 74 72 35 74 34 72 65 36 74 72 72 77 } //1 5tr5t4re6trrw
		$a_01_1 = {5b 43 54 52 4c 5d } //1 [CTRL]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}