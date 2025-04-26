
rule TrojanSpy_Win32_Bancos_ZB{
	meta:
		description = "TrojanSpy:Win32/Bancos.ZB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 2a 74 2a 75 61 40 6c 69 7a 2a 61 6e 2a 64 6f 2e 2a 64 6c 2a 40 6c } //1 a*t*ua@liz*an*do.*dl*@l
		$a_01_1 = {2f 2f 3a 70 40 74 74 68 } //1 //:p@tth
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}