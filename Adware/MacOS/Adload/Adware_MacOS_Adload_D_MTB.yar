
rule Adware_MacOS_Adload_D_MTB{
	meta:
		description = "Adware:MacOS/Adload.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 00 8e 0a 06 e0 23 00 9d 0b 0c ef 22 00 ad 0b 0f ea 22 00 da 0b 34 ab 23 00 8e 0c 82 02 00 00 90 0e 0c b2 22 00 b9 0f 05 b0 22 00 b2 11 f0 01 9a 23 00 dd 13 09 e8 22 00 eb 13 09 e3 22 00 8d 14 30 f1 22 00 95 16 a5 01 9a 23 00 de 17 0a ab 22 00 f2 17 13 93 22 00 85 18 ed 01 00 00 f2 19 05 b4 22 00 90 1b 20 9a 23 00 ce 21 05 8e 22 00 d5 } //00 00 
	condition:
		any of ($a_*)
 
}