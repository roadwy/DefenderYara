
rule Worm_Win32_Siwdivy_A{
	meta:
		description = "Worm:Win32/Siwdivy.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {c6 06 41 c6 46 01 3a c6 46 02 5c c6 46 03 00 56 e8 90 01 04 83 f8 02 75 06 90 00 } //1
		$a_01_1 = {eb 06 20 2e 6c 6e 6b 00 68 } //1
		$a_01_2 = {eb 06 2c 70 30 31 20 00 68 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}