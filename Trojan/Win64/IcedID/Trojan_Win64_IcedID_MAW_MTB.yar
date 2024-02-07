
rule Trojan_Win64_IcedID_MAW_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 4f 32 42 4d 52 61 4e 38 33 44 77 68 65 69 70 35 79 72 74 57 79 74 74 61 58 64 39 48 } //01 00  CO2BMRaN83Dwheip5yrtWyttaXd9H
		$a_01_1 = {47 47 75 68 6e 6a 61 73 62 75 68 62 61 73 6a 61 6e 73 6a } //01 00  GGuhnjasbuhbasjansj
		$a_01_2 = {47 6e 65 4e 73 58 75 37 34 59 47 34 37 66 38 42 4b 68 37 4a 34 46 69 59 44 31 } //01 00  GneNsXu74YG47f8BKh7J4FiYD1
		$a_01_3 = {48 4a 54 31 70 58 39 6c 45 4c 79 38 38 54 58 4f 6e 4b 35 62 68 4f 42 64 64 } //01 00  HJT1pX9lELy88TXOnK5bhOBdd
		$a_01_4 = {48 62 56 51 75 35 6a 50 6a 78 64 79 74 47 54 70 4e 4d 38 50 50 79 63 4e 4d 68 42 } //01 00  HbVQu5jPjxdytGTpNM8PPycNMhB
		$a_01_5 = {48 78 46 72 4f 43 66 57 4e 5a 76 53 6c 64 5a 39 79 33 44 41 6c 66 45 6e 4b } //00 00  HxFrOCfWNZvSldZ9y3DAlfEnK
	condition:
		any of ($a_*)
 
}