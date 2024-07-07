
rule Backdoor_Win32_Bergat_A{
	meta:
		description = "Backdoor:Win32/Bergat.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 00 61 00 6b 00 65 00 4d 00 65 00 73 00 73 00 61 00 67 00 65 00 } //1 FakeMessage
		$a_01_1 = {43 00 59 00 42 00 45 00 52 00 47 00 41 00 54 00 45 00 50 00 41 00 53 00 53 00 } //1 CYBERGATEPASS
		$a_01_2 = {43 00 79 00 62 00 65 00 72 00 47 00 61 00 74 00 65 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //1 CyberGateKeylogger
		$a_01_3 = {5b 00 45 00 78 00 65 00 63 00 75 00 74 00 65 00 5d 00 } //1 [Execute]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}