
rule Trojan_Win64_Clipbanker_ARR_MTB{
	meta:
		description = "Trojan:Win64/Clipbanker.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 00 6c 00 65 00 61 00 6e 00 53 00 79 00 73 00 74 00 65 00 6d 00 5f 00 31 00 37 00 35 00 38 00 32 00 } //10 CleanSystem_17582
		$a_01_1 = {54 42 6d 35 56 51 73 4e 34 39 4e 37 70 55 61 71 6a 76 6f 76 61 38 6a 6f 77 59 46 74 69 35 4e 77 7a 4c } //6 TBm5VQsN49N7pUaqjvova8jowYFti5NwzL
		$a_01_2 = {31 41 74 45 6f 58 39 67 6d 54 5a 43 77 32 59 52 50 35 4a 52 67 54 53 61 67 64 4c 50 59 63 44 72 51 43 } //4 1AtEoX9gmTZCw2YRP5JRgTSagdLPYcDrQC
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*6+(#a_01_2  & 1)*4) >=20
 
}