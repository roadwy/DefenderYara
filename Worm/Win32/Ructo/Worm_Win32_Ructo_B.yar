
rule Worm_Win32_Ructo_B{
	meta:
		description = "Worm:Win32/Ructo.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3a 00 5c 00 74 00 75 00 64 00 6f 00 5c 00 62 00 61 00 69 00 78 00 61 00 } //1 :\tudo\baixa
		$a_01_1 = {00 00 76 00 6f 00 63 00 65 00 3d 00 00 00 10 00 00 00 45 00 6e 00 76 00 69 00 61 00 64 00 6f 00 3d 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}