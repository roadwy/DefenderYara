
rule PWS_Win32_Lolyda_BE{
	meta:
		description = "PWS:Win32/Lolyda.BE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 14 01 80 c2 07 80 f2 05 80 ea 07 88 10 40 4e 75 ee } //2
		$a_01_1 = {61 63 3d 75 70 26 7a 7a 7a 3d 65 78 6b 26 64 64 32 3d } //1 ac=up&zzz=exk&dd2=
		$a_01_2 = {61 63 3d 75 70 26 7a 7a 7a 3d 6f 6c 26 64 64 32 3d } //1 ac=up&zzz=ol&dd2=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}