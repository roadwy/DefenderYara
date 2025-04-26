
rule PWS_Win32_Stimilina_C_bit{
	meta:
		description = "PWS:Win32/Stimilina.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 67 69 6e 3d 25 73 26 70 61 73 73 77 3d 25 73 } //1 login=%s&passw=%s
		$a_01_1 = {53 00 74 00 65 00 61 00 6d 00 2e 00 65 00 78 00 65 00 } //1 Steam.exe
		$a_03_2 = {b8 44 65 00 00 66 89 46 ?? b8 74 6f 00 00 66 89 46 ?? b8 75 72 00 00 66 89 46 ?? b8 73 21 00 00 66 89 46 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}