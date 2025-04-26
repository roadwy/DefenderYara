
rule PWS_BAT_Parple_B{
	meta:
		description = "PWS:BAT/Parple.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {01 0b 07 16 1f 64 9c 07 17 1f 55 9c 07 18 1f 40 9c 07 19 1f 37 } //1
		$a_01_1 = {01 13 08 11 08 16 1f 12 9c 11 08 17 1f 34 9c 11 08 18 1f 56 9c 11 08 19 1f 78 } //1
		$a_01_2 = {06 1f 10 1f 3d 9c 06 1f 11 1f 40 9c 06 1f 12 1f 4b 9c 06 1f 13 1f 51 9c 06 1f 14 1f 63 9c 06 1f 15 1f 6a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}