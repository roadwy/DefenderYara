
rule Worm_Win32_Vobfus_BD_MTB{
	meta:
		description = "Worm:Win32/Vobfus.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {be 40 00 17 bf 40 00 38 bf 40 00 59 bf 40 00 8b bf 40 00 8d bf 40 00 8d bf 40 00 ae bf 40 00 cf bf 40 00 d4 bf 40 00 f5 bf 40 00 16 c0 40 00 37 } //2
		$a_01_1 = {30 41 00 c5 30 41 00 e6 30 41 00 02 31 41 00 23 31 41 00 44 31 41 00 65 31 41 00 75 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}