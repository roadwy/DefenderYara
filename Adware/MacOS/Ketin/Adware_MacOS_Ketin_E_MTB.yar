
rule Adware_MacOS_Ketin_E_MTB{
	meta:
		description = "Adware:MacOS/Ketin.E!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 45 b0 31 c0 48 8d 95 60 ff ff ff 48 89 02 48 89 52 08 48 b9 00 00 00 32 30 00 00 00 48 89 4a 10 48 8d 0d 93 04 00 00 48 89 4a 18 48 8d 0d 9e 04 00 00 48 89 4a 20 48 89 42 28 31 ff } //1
		$a_01_1 = {31 c0 4c 8d b5 50 ff ff ff 49 89 06 4d 89 76 08 48 b9 00 00 00 20 20 00 00 00 49 89 4e 10 49 c7 46 18 ff ff ff ff 48 8d 9d 20 ff ff ff 48 89 03 48 89 5b 08 48 b9 00 00 00 32 30 00 00 00 48 89 4b 10 48 8d 0d b8 ee ff ff 48 89 4b 18 48 8d 0d c3 ee ff ff 48 89 4b 20 48 89 43 28 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}