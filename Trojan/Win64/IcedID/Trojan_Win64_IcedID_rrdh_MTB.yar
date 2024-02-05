
rule Trojan_Win64_IcedID_rrdh_MTB{
	meta:
		description = "Trojan:Win64/IcedID.rrdh!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8a 0a 48 8d 52 02 88 4c 24 30 8a 44 24 30 83 e8 21 88 44 24 30 c0 64 24 30 04 8a 44 24 30 88 44 24 38 8a 42 ff 88 44 24 30 8a 44 24 30 83 e8 34 88 44 24 30 0f b6 44 24 38 8a 4c 24 30 0b c8 88 4c 24 38 0f b6 44 24 38 8a 4c 24 40 33 c8 88 4c 24 38 fe 44 24 40 8a 44 24 38 41 88 00 49 ff c0 83 44 24 48 ff 8b 44 24 48 75 95 } //01 00 
		$a_01_1 = {42 74 74 66 6a 73 69 72 7a 7a 53 68 6e 62 77 61 79 61 67 } //01 00 
		$a_01_2 = {44 78 68 63 68 64 62 6c 76 4f 76 75 45 77 74 75 67 6e 74 62 75 } //00 00 
	condition:
		any of ($a_*)
 
}