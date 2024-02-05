
rule Adware_MacOS_Synataeb_C_MTB{
	meta:
		description = "Adware:MacOS/Synataeb.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {10 10 10 40 90 01 10 80 01 e0 02 60 10 70 10 10 10 a0 06 50 10 40 90 01 90 01 50 10 30 20 c0 01 80 03 f0 05 20 10 90 01 90 03 b0 01 c0 01 80 01 90 13 90 09 30 60 20 4e d2 01 20 50 20 20 20 20 30 20 20 20 10 20 } //00 00 
	condition:
		any of ($a_*)
 
}