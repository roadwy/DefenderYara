
rule Adware_MacOS_pirrit_K_MTB{
	meta:
		description = "Adware:MacOS/pirrit.K!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {c7 05 b3 2d 10 00 01 00 00 00 31 ff be 0a 00 00 00 e8 47 4a 0c 00 48 8d 35 05 23 0d 00 48 89 c7 e8 3e 4a 0c 00 31 ff be 0a 00 00 00 e8 2c 4a 0c 00 48 8d 35 d9 22 0d 00 48 89 c7 e8 23 4a 0c 00 31 ff be 0a 00 00 00 e8 11 4a 0c 00 48 8d 35 af 22 0d 00 48 89 c7 e8 08 4a 0c 00 31 ff be 0a 00 00 00 e8 f6 49 0c 00 48 8d 35 83 22 0d 00 48 89 c7 e8 ed 49 0c 00 31 ff be 0a 00 00 00 e8 db 49 0c 00 48 8d 35 59 22 0d 00 48 89 c7 e8 d2 49 0c 00 31 ff be 0a 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}