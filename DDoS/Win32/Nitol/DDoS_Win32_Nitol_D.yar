
rule DDoS_Win32_Nitol_D{
	meta:
		description = "DDoS:Win32/Nitol.D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 68 74 6d 47 45 54 20 5e 26 26 25 24 25 24 5e 25 24 23 5e 26 2a 2a 28 2a 28 28 26 2a 5e 25 24 23 23 24 25 5e 26 2a 28 2a 26 5e 25 24 25 5e 26 2a 2e 68 74 6d 47 45 54 20 5e } //1 .htmGET ^&&%$%$^%$#^&**(*((&*^%$##$%^&*(*&^%$%^&*.htmGET ^
		$a_01_1 = {ff d5 68 00 e9 a4 35 66 89 } //1
		$a_01_2 = {33 d2 8a 11 03 c2 8b c8 25 ff ff 00 00 c1 e9 10 03 c8 8b c1 c1 e8 10 03 c1 f7 d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}