
rule PWS_BAT_Parple_A{
	meta:
		description = "PWS:BAT/Parple.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {01 13 09 11 09 16 1f 12 9c 11 09 17 1f 34 9c 11 09 18 1f 56 9c 11 09 19 1f 78 } //1
		$a_01_1 = {20 33 d4 00 00 0a } //1
		$a_01_2 = {20 f2 03 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}