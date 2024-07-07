
rule Trojan_Win32_Androm_A_MTB{
	meta:
		description = "Trojan:Win32/Androm.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {6a 04 68 00 30 00 00 68 a1 a4 ad 1f 6a 00 e8 } //1
		$a_00_1 = {6a 04 68 00 30 00 00 68 b4 d3 de 1d 6a 00 e8 } //1
		$a_00_2 = {51 54 6a 40 68 77 5b 00 00 50 e8 } //1
		$a_80_3 = {76 4a 53 75 59 32 74 76 6d 7a 45 6f 31 55 32 } //vJSuY2tvmzEo1U2  1
		$a_80_4 = {44 68 32 53 4a 6d 42 52 50 51 6c 44 5a } //Dh2SJmBRPQlDZ  1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}