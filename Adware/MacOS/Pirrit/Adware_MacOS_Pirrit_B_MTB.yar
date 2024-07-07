
rule Adware_MacOS_Pirrit_B_MTB{
	meta:
		description = "Adware:MacOS/Pirrit.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {12 77 8f f0 ec c9 cc 29 7e e1 0d 6f c1 35 80 69 03 48 1d 46 c7 50 90 8a 3b ab 91 b1 61 24 63 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}