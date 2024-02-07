
rule Adware_MacOS_AdLoad_B_MTB{
	meta:
		description = "Adware:MacOS/AdLoad.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 83 f9 04 0f 82 90 01 02 00 00 48 89 c2 8b 00 8b 74 0a fc c1 e0 03 48 01 c8 48 31 f0 48 ba 69 2d 38 eb 08 ea df 9d 48 89 d7 48 0f af c2 48 89 c2 48 c1 ea 2f 48 31 f0 90 00 } //01 00 
		$a_03_1 = {44 8b 68 04 48 89 df 90 01 03 02 00 48 85 c0 74 dc 8a 18 84 db 74 d6 41 83 c5 07 41 83 e5 f8 4c 89 f9 4c 29 e9 48 c1 e9 03 31 d2 90 00 } //01 00 
		$a_01_2 = {75 75 69 64 5f 67 65 6e 65 72 61 74 65 5f 72 61 6e 64 6f 6d } //01 00  uuid_generate_random
		$a_01_3 = {6b 65 79 45 6e 75 6d 65 72 61 74 6f 72 } //00 00  keyEnumerator
	condition:
		any of ($a_*)
 
}