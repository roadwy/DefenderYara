
rule Worm_Win32_Gate_A{
	meta:
		description = "Worm:Win32/Gate.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 41 46 45 4d 4f 44 45 20 20 3a 20 20 20 54 68 69 73 20 57 4f 52 4d 20 69 73 20 64 65 73 69 67 6e 65 64 20 6f 6e 6c 79 20 74 6f 20 74 65 73 74 } //1 SAFEMODE  :   This WORM is designed only to test
		$a_01_1 = {77 69 74 68 20 72 65 73 70 65 63 74 20 53 61 66 65 74 79 47 61 74 65 2e 72 75 } //1 with respect SafetyGate.ru
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}