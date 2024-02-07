
rule Trojan_AndroidOS_Fakeapp_M{
	meta:
		description = "Trojan:AndroidOS/Fakeapp.M,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 57 70 6d 62 32 63 6a 4a 47 35 48 61 6d 4a 76 63 32 4a 6e 52 32 5a 76 5a 6e 64 6d 4a 43 4e 69 62 57 63 6a 62 6d 5a 33 61 32 78 6e 49 79 52 73 62 55 64 6d 62 32 5a 33 5a 69 51 } //01 00  ZWpmb2cjJG5HamJvc2JnR2ZvZndmJCNibWcjbmZ3a2xnIyRsbUdmb2Z3ZiQ
		$a_01_1 = {5a 6d 31 79 64 6d 5a 32 5a 6c 64 73 59 6e 42 33 52 6e 73 } //01 00  Zm1ydmZ2ZldsYnB3Rns
		$a_01_2 = {5a 57 70 6d 62 32 63 6a 4a 47 35 48 61 6d 4a 76 63 32 4a 6e 53 6d 31 7a 64 6e 63 6b } //00 00  ZWpmb2cjJG5HamJvc2JnSm1zdnck
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_Fakeapp_M_2{
	meta:
		description = "Trojan:AndroidOS/Fakeapp.M,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 73 20 6e 6f 74 20 61 20 64 61 6e 67 65 72 6f 75 73 20 70 65 72 6d 69 73 73 69 6f 6e 20 6f 72 20 73 70 65 63 69 61 6c 20 70 65 72 6d 69 73 73 69 6f 6e } //01 00  is not a dangerous permission or special permission
		$a_01_1 = {73 79 73 74 65 6d 50 68 6f 74 6f 4c 69 73 74 73 } //01 00  systemPhotoLists
		$a_01_2 = {77 72 65 73 75 6c 74 4d 61 70 64 61 64 61 } //01 00  wresultMapdada
		$a_01_3 = {74 68 65 20 61 6e 72 20 70 72 6f 63 65 73 73 20 66 6f 75 6e 64 } //00 00  the anr process found
	condition:
		any of ($a_*)
 
}