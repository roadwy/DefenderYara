
rule PUA_MacOS_Adload_E_MTB{
	meta:
		description = "PUA:MacOS/Adload.E!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 89 e5 48 83 ec 50 48 89 f8 31 c9 31 d2 48 89 75 f8 48 8b 75 f8 48 89 7d c0 48 89 f7 89 ce 48 89 45 b8 e8 d7 00 00 00 48 89 45 f0 48 83 7d f0 ff 0f 85 12 00 00 00 48 8b 75 f8 48 8d 7d d8 } //01 00 
		$a_00_1 = {69 6e 6a 65 63 74 6f 72 } //01 00 
		$a_00_2 = {6b 65 79 65 6e 75 6d 65 72 61 74 6f 72 } //01 00 
		$a_00_3 = {5a 4c 31 32 64 65 63 72 79 70 74 5f 62 79 74 65 50 6d 50 4b 6d } //00 00 
		$a_00_4 = {5d 04 00 } //00 7c 
	condition:
		any of ($a_*)
 
}