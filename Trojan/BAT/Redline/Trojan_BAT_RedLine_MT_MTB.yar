
rule Trojan_BAT_RedLine_MT_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 15 a2 09 09 0b 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 35 00 00 00 0c 00 00 00 12 00 00 00 31 } //01 00 
		$a_01_1 = {39 32 61 64 39 38 65 64 2d 38 63 33 62 2d 34 63 63 62 2d 39 34 66 39 2d 63 35 30 64 61 37 36 34 64 35 34 38 } //01 00  92ad98ed-8c3b-4ccb-94f9-c50da764d548
		$a_01_2 = {4a 61 6d 62 6f } //01 00  Jambo
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_4 = {50 65 72 76 61 73 69 76 65 4d 69 6e 64 43 68 61 6c 6c 65 6e 67 65 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00  PervasiveMindChallenge.Properties
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_6 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_7 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}