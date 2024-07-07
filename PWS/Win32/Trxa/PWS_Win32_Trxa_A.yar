
rule PWS_Win32_Trxa_A{
	meta:
		description = "PWS:Win32/Trxa.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 71 3d 61 74 72 61 78 73 74 65 61 6c 65 72 } //1
		$a_01_1 = {41 74 72 61 78 20 53 74 65 61 6c 65 72 } //1 Atrax Stealer
		$a_01_2 = {8a 07 3c 2d 74 36 3c 5f 74 32 3c 2e 74 2e 3c 7e 74 2a 3c 20 75 05 c6 06 2b eb 25 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}