
rule Virus_Win32_Almanahe_PABR_MTB{
	meta:
		description = "Virus:Win32/Almanahe.PABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b9 9e 04 00 00 80 04 19 59 e2 fa } //1
		$a_01_1 = {06 ec a4 bf 8c 34 bf da 94 a6 b3 ce 4e e4 4c 5c cc 95 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}