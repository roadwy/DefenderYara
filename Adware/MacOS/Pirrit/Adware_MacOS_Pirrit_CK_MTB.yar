
rule Adware_MacOS_Pirrit_CK_MTB{
	meta:
		description = "Adware:MacOS/Pirrit.CK!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 74 91 52 69 61 bf 72 1f 01 09 6b e8 17 9f 1a 08 01 00 12 e8 17 04 b9 e8 0f 42 f9 e9 17 44 b9 29 7d 40 93 0a 01 80 d2 28 21 0a 9b 08 01 40 f9 69 27 00 90 29 41 33 91 29 01 40 b9 ca 95 91 52 aa 08 b1 72 29 01 0a 4a e9 03 09 4b 29 7d 40 93 08 01 09 8b 00 01 1f d6 } //1
		$a_01_1 = {e9 bd 83 52 09 f6 b7 72 1f 01 09 6b e8 17 9f 1a 08 01 00 12 e8 57 02 b9 e8 2f 41 f9 e9 57 42 b9 29 7d 40 93 0a 01 80 d2 28 21 0a 9b 08 01 40 f9 69 27 00 90 29 c1 3d 91 29 01 40 b9 0a 15 9d 52 ea 80 bf 72 29 01 0a 4a e9 03 09 4b 29 7d 40 93 08 01 09 8b 00 01 1f d6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}