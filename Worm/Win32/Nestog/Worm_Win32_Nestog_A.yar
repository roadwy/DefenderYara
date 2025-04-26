
rule Worm_Win32_Nestog_A{
	meta:
		description = "Worm:Win32/Nestog.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 06 46 32 c1 88 07 47 49 0b c9 75 f3 } //1
		$a_01_1 = {eb 0c 43 3a 5c 67 68 6f 73 74 79 2e 64 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}