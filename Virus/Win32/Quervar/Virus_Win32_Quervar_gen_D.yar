
rule Virus_Win32_Quervar_gen_D{
	meta:
		description = "Virus:Win32/Quervar.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 14 02 8b ca 80 c1 bf 80 e9 0d 72 14 80 e9 0d 72 1f 80 c1 fa 80 e9 0d 72 07 80 e9 0d 72 12 eb 1e 81 e2 ff 00 00 00 83 c2 0d 8b 0b 88 14 01 eb 0e } //1
		$a_01_1 = {36 69 73 74 33 39 66 69 75 38 72 6a 6f 00 00 00 2d 00 75 00 70 00 70 00 20 00 00 00 37 38 69 38 37 36 75 79 34 35 79 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}