
rule Worm_Win32_Flame_gen_D{
	meta:
		description = "Worm:Win32/Flame.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 29 83 f8 0a 74 11 83 e8 5a f7 d8 1b c0 25 f8 07 00 00 83 c0 08 eb 57 } //1
		$a_01_1 = {33 c0 57 66 8b 46 09 8d 7e 0b 50 57 } //1
		$a_01_2 = {85 c0 75 11 ff d6 3d 30 04 00 00 74 08 53 53 53 ff d6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}