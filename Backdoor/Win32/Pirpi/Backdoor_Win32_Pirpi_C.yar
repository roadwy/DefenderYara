
rule Backdoor_Win32_Pirpi_C{
	meta:
		description = "Backdoor:Win32/Pirpi.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 54 14 18 8a 1c 38 32 da 88 1c 38 40 3b c1 7c e0 } //1
		$a_01_1 = {8a 44 04 10 30 44 0e 04 41 3b ca 72 e5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}