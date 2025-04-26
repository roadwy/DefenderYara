
rule Spammer_Win32_Tedroo_F{
	meta:
		description = "Spammer:Win32/Tedroo.F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8c b5 b8 34 24 40 cd 9e 31 53 1c b4 f3 43 5a e6 fe 4c 4f 47 47 45 52 08 0b 4f 42 0b 73 c9 6b 64 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Spammer_Win32_Tedroo_F_2{
	meta:
		description = "Spammer:Win32/Tedroo.F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c3 8b c1 18 cc cc 08 cc 51 c7 dc 42 71 b8 44 23 40 00 8d 49 42 fa 01 42 f7 42 b2 1a 32 d2 83 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}