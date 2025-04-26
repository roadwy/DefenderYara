
rule TrojanSpy_Win32_Banker_VBO{
	meta:
		description = "TrojanSpy:Win32/Banker.VBO,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_02_0 = {65 78 65 2e [0-15] 5c 3a 63 } //2
		$a_00_1 = {5c 65 72 61 77 74 66 6f 53 5c 4d 4c 4b 48 } //2 \erawtfoS\MLKH
		$a_00_2 = {41 25 75 25 74 25 6f 25 43 25 6f 25 6d 25 70 25 6c 25 65 25 74 25 65 25 } //1 A%u%t%o%C%o%m%p%l%e%t%e%
		$a_00_3 = {25 6d 25 65 25 6e 25 73 25 61 25 67 25 65 25 6d 25 } //1 %m%e%n%s%a%g%e%m%
		$a_00_4 = {76 65 72 69 66 69 71 75 65 20 61 20 73 75 61 20 63 6f 6e 74 61 } //1 verifique a sua conta
		$a_00_5 = {73 65 6e 68 61 } //1 senha
		$a_00_6 = {67 6d 61 69 6c } //1 gmail
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=8
 
}