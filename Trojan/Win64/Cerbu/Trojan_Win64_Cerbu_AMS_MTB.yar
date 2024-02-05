
rule Trojan_Win64_Cerbu_AMS_MTB{
	meta:
		description = "Trojan:Win64/Cerbu.AMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f 1f 80 00 00 00 00 0f b6 14 0b 48 8d 49 01 80 f2 71 41 ff c0 88 51 ff 48 8b 54 24 70 49 63 c0 48 3b c2 } //01 00 
		$a_01_1 = {48 89 44 24 28 33 d2 88 44 24 40 89 44 24 20 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}