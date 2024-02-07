
rule Trojan_BAT_SnakeKeylogger_MO_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {57 17 a2 1f 09 01 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 79 00 00 00 0a 00 00 00 36 00 00 00 3e 00 00 00 31 } //02 00 
		$a_01_1 = {74 65 73 74 6c 6f 67 69 6e 2e 50 72 6f 70 65 72 74 69 65 73 } //02 00  testlogin.Properties
		$a_01_2 = {65 37 38 38 36 37 64 61 2d 63 30 35 62 2d 34 34 36 37 2d 39 39 36 34 2d 63 62 63 37 31 39 66 65 36 64 66 63 } //02 00  e78867da-c05b-4467-9964-cbc719fe6dfc
		$a_01_3 = {4a 65 6c 65 73 69 73 } //02 00  Jelesis
		$a_01_4 = {73 00 65 00 6c 00 65 00 63 00 74 00 20 00 63 00 6f 00 75 00 6e 00 74 00 28 00 2a 00 29 00 20 00 66 00 72 00 6f 00 6d 00 20 00 75 00 73 00 65 00 72 00 70 00 77 00 64 00 20 00 77 00 68 00 65 00 72 00 65 00 20 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 3d 00 } //01 00  select count(*) from userpwd where username=
		$a_01_5 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00  TransformFinalBlock
	condition:
		any of ($a_*)
 
}