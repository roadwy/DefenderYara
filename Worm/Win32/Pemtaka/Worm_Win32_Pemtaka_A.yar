
rule Worm_Win32_Pemtaka_A{
	meta:
		description = "Worm:Win32/Pemtaka.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3c aa 75 0e 83 ef 32 83 c3 32 81 ff 2f f8 ff ff 7f } //1
		$a_01_1 = {5f 5f 43 34 41 33 38 45 46 34 5f 32 32 33 34 5f 34 30 33 35 5f 42 31 44 34 5f 38 42 41 30 44 34 31 38 32 31 38 30 5f 5f } //1 __C4A38EF4_2234_4035_B1D4_8BA0D4182180__
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}