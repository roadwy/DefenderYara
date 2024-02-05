
rule Trojan_Win32_Ekstak_AMK_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.AMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {62 6f 72 6c 6e 64 6d 6d } //borlndmm  03 00 
		$a_80_1 = {4c 6f 63 61 6c 5c 46 61 73 74 4d 4d 5f 50 49 44 } //Local\FastMM_PID  03 00 
		$a_80_2 = {73 68 6f 75 6c 64 20 6e 65 76 65 72 20 67 65 74 20 68 65 72 65 } //should never get here  03 00 
		$a_80_3 = {44 48 4c 4c 50 50 54 54 58 58 } //DHLLPPTTXX  03 00 
		$a_80_4 = {53 65 61 72 63 68 50 61 74 68 57 } //SearchPathW  03 00 
		$a_80_5 = {41 6c 6c 20 50 69 63 74 75 72 65 20 46 69 6c 65 73 7c 2a 2e 62 6d 70 3b 2a 2e 77 6d 66 3b 2a 2e 65 6d 66 3b 2a 2e 69 63 6f 3b 2a 2e 64 69 62 3b 2a 2e 63 75 72 3b 2a 2e 67 69 66 3b 2a } //All Picture Files|*.bmp;*.wmf;*.emf;*.ico;*.dib;*.cur;*.gif;*  03 00 
		$a_80_6 = {4c 6f 61 64 65 72 4c 6f 63 6b } //LoaderLock  00 00 
	condition:
		any of ($a_*)
 
}