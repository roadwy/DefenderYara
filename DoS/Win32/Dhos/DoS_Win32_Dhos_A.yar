
rule DoS_Win32_Dhos_A{
	meta:
		description = "DoS:Win32/Dhos.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 74 74 61 63 6b } //01 00  attack
		$a_01_1 = {68 61 63 6b 65 72 } //01 00  hacker
		$a_01_2 = {74 68 63 2d 73 73 6c 2d 64 6f 73 } //00 00  thc-ssl-dos
	condition:
		any of ($a_*)
 
}