
rule PWS_Win32_Predator_F_bit{
	meta:
		description = "PWS:Win32/Predator.F!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a ca 8a c3 d2 e8 24 01 88 44 15 f8 42 83 fa 08 7c ee } //1
		$a_01_1 = {8a 14 3e 80 e2 01 d2 e2 02 c2 4e 41 83 f9 07 7e ef } //1
		$a_03_2 = {33 d2 8a 5c 11 90 01 01 8d 3c 11 42 88 5f 02 f6 c2 01 74 09 8a 44 35 90 01 01 32 c3 88 47 02 83 fa 07 7c e2 8a 41 90 01 01 22 01 32 41 90 01 01 46 88 41 90 01 01 83 c1 08 83 fe 08 7e cc 90 00 } //1
		$a_03_3 = {83 f9 0c 73 1f 8a 84 0d 90 01 04 32 c2 88 84 0d 90 01 04 41 89 8d 90 01 04 8a 95 90 01 04 eb dc 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}