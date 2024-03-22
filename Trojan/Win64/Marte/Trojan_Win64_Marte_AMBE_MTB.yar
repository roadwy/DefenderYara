
rule Trojan_Win64_Marte_AMBE_MTB{
	meta:
		description = "Trojan:Win64/Marte.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {4c 8d 4c 24 90 01 01 ba 90 01 04 41 b8 20 00 00 00 48 8b cb ff 15 90 01 04 85 c0 74 90 01 01 48 c7 44 24 28 90 01 04 45 33 c9 4c 8b c3 c7 44 24 20 90 01 04 33 d2 33 c9 ff 15 90 01 04 48 8b c8 ba 90 01 04 ff 15 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 54 68 72 65 61 64 } //01 00  CreateThread
		$a_01_2 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00  WaitForSingleObject
	condition:
		any of ($a_*)
 
}