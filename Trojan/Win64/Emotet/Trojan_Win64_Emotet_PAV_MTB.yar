
rule Trojan_Win64_Emotet_PAV_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 0b 49 ff c3 48 8d 5b 04 33 cd 0f b6 c1 66 41 89 00 0f b7 c1 c1 e9 10 66 c1 e8 08 4d 8d 40 08 66 41 89 40 90 01 01 0f b6 c1 66 c1 e9 08 66 41 89 40 90 01 01 66 41 89 48 90 01 01 4d 3b d9 72 90 00 } //01 00 
		$a_03_1 = {8b 0b 49 ff c3 48 8d 5b 04 33 cd 41 88 08 0f b7 c1 c1 e9 10 66 c1 e8 08 4d 8d 40 04 41 88 40 90 01 01 41 88 48 90 01 01 66 c1 e9 08 41 88 48 90 01 01 4d 3b d9 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}