
rule PWS_Win64_HighCount_B_dha{
	meta:
		description = "PWS:Win64/HighCount.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {60 00 00 00 05 81 a7 3c a3 a3 68 4a b4 58 1a 60 6b ab 8f d6 01 00 00 00 04 5d 88 8a eb 1c c9 11 9f e8 08 00 2b 10 48 60 02 00 00 00 } //1
		$a_01_1 = {31 66 32 61 30 34 37 62 2d 39 36 64 38 2d 34 38 38 65 2d 62 63 39 62 2d 31 64 35 65 30 30 30 30 30 30 30 30 } //1 1f2a047b-96d8-488e-bc9b-1d5e00000000
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}