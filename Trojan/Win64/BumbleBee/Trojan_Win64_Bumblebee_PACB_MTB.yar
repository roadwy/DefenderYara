
rule Trojan_Win64_Bumblebee_PACB_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.PACB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 8b 42 58 05 61 34 13 00 31 81 ac 00 00 00 48 8b 05 90 01 04 8b 88 fc 00 00 00 8b c2 41 31 8a b0 00 00 00 48 8b 0d 90 01 04 0f af c2 01 05 90 01 04 ff c2 3b 51 54 76 c4 90 00 } //01 00 
		$a_03_1 = {8b 55 f8 48 8b 05 90 01 04 8b 48 4c 8b 45 f0 33 0d 90 01 04 0f af d1 0f af c2 89 45 f8 48 8b 05 90 01 04 8b 88 e0 00 00 00 33 0d 90 01 04 0b 88 f0 00 00 00 09 0d 90 01 04 44 03 c3 8b 4d 20 8b 45 ec 23 c8 44 3b c1 75 b2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}