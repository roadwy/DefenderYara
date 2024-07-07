
rule Trojan_Win32_Razmeeg_A{
	meta:
		description = "Trojan:Win32/Razmeeg.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 71 04 00 00 01 02 50 06 17 59 91 61 d2 81 04 00 00 01 06 17 59 0a 06 16 30 dd 2a 00 } //1
		$a_00_1 = {2f 00 7a 00 65 00 6d 00 72 00 61 00 2f 00 67 00 61 00 74 00 65 00 2e 00 70 00 68 00 70 00 } //1 /zemra/gate.php
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}