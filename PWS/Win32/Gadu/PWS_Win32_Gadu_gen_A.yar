
rule PWS_Win32_Gadu_gen_A{
	meta:
		description = "PWS:Win32/Gadu.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 64 75 63 74 20 20 20 3a 20 50 61 73 73 54 6f 6f 6c } //2 Product   : PassTool
		$a_01_1 = {43 6f 70 79 72 69 67 68 74 20 3a 20 62 79 20 6d 61 53 73 20 5b 63 34 66 5d } //3 Copyright : by maSs [c4f]
		$a_01_2 = {61 20 7a 20 47 61 64 75 } //1 a z Gadu
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1) >=6
 
}