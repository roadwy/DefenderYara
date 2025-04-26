
rule Adware_MacOS_Adload_AC_MTB{
	meta:
		description = "Adware:MacOS/Adload.AC!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 48 8b 77 08 8b 57 10 48 8b 3f e8 db 30 21 00 85 c0 7d 09 e8 cc 30 21 00 8b 00 f7 d8 } //1
		$a_01_1 = {55 48 89 e5 48 89 fb 48 8b 3b 48 8b 73 08 8b 53 10 8b 4b 14 44 8b 43 18 44 8b 4b 1c e8 af 2d 21 00 31 d2 48 83 f8 ff 75 0a e8 5a 2d 21 00 48 63 10 31 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}