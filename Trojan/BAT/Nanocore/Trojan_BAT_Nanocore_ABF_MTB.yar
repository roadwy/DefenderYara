
rule Trojan_BAT_Nanocore_ABF_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {57 9d a2 29 09 0b 00 00 00 00 00 00 00 00 00 00 01 00 00 00 96 00 00 00 51 00 00 00 48 02 00 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_3 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_5 = {24 39 31 32 65 66 61 39 32 2d 36 31 30 62 2d 34 30 66 32 2d 61 32 38 32 2d 32 32 64 31 62 36 66 36 34 65 30 31 } //00 00  $912efa92-610b-40f2-a282-22d1b6f64e01
	condition:
		any of ($a_*)
 
}