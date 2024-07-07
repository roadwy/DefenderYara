
rule PWS_Win32_Ldpinch_CB{
	meta:
		description = "PWS:Win32/Ldpinch.CB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 65 6c 6c 6f 2e 65 78 65 00 03 00 00 00 9a 9a 9a 31 32 33 2e 74 78 74 00 1d 16 00 } //1
		$a_01_1 = {46 54 65 e7 65 76 53 73 37 65 87 65 87 68 78 35 67 65 76 53 73 57 53 75 67 35 73 76 57 35 67 67 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}