
rule Backdoor_Win32_Wykcores_A{
	meta:
		description = "Backdoor:Win32/Wykcores.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 83 c6 48 83 c7 44 83 fb 04 75 b6 33 c0 89 45 0c 33 c0 89 45 14 33 c0 89 45 1c b0 01 81 c4 34 02 00 00 5d 5f 5e 5b c3 } //2
		$a_01_1 = {8b cb 8a 55 b8 d2 e2 30 10 43 40 83 fb 10 75 f0 } //2
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 53 78 6c } //1 SOFTWARE\Classes\Sxl
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}