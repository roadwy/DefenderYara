
rule Constructor_Win32_Cuteqq{
	meta:
		description = "Constructor:Win32/Cuteqq,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 74 74 70 3a 2f 2f 57 77 77 2e 43 75 74 65 51 71 2e 43 6e } //3 Http://Www.CuteQq.Cn
		$a_01_1 = {76 61 72 20 4f 72 68 32 3d 77 69 6e 64 6f 77 5b 22 4d 61 74 68 22 5d 5b 22 72 61 6e 64 6f 6d 22 5d 28 29 2a 72 52 61 47 45 79 6b 55 31 3b } //4 var Orh2=window["Math"]["random"]()*rRaGEykU1;
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*4) >=7
 
}