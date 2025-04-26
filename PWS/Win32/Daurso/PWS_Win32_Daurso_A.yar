
rule PWS_Win32_Daurso_A{
	meta:
		description = "PWS:Win32/Daurso.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 14 11 03 c6 30 10 41 3b 4d 14 72 02 33 c9 46 3b 75 0c 72 e5 } //1
		$a_01_1 = {80 f9 0a 75 04 4e 48 eb f0 83 c6 fc 56 83 c7 05 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}