
rule DoS_Win32_Dhos_A{
	meta:
		description = "DoS:Win32/Dhos.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 74 74 61 63 6b } //1 attack
		$a_01_1 = {68 61 63 6b 65 72 } //1 hacker
		$a_01_2 = {74 68 63 2d 73 73 6c 2d 64 6f 73 } //1 thc-ssl-dos
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}