
rule TrojanSpy_Win32_Fledul{
	meta:
		description = "TrojanSpy:Win32/Fledul,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 23 63 25 70 25 6c 25 } //1 .#c%p%l%
		$a_01_1 = {5c 2a 70 2a 72 23 6f 23 63 25 65 25 73 25 73 25 78 25 78 25 } //1 \*p*r#o#c%e%s%s%x%x%
		$a_01_2 = {67 2a 65 40 74 40 6d 40 61 40 69 23 6c 23 } //1 g*e@t@m@a@i#l#
		$a_01_3 = {72 25 65 25 67 2a 20 2a 61 2a 64 2a 64 23 } //1 r%e%g* *a*d*d#
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}