
rule Trojan_Win64_Iceid_PD_MTB{
	meta:
		description = "Trojan:Win64/Iceid.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 f7 f1 48 8b c2 48 8b 4c 24 90 01 01 66 3b f6 74 45 90 00 } //01 00 
		$a_03_1 = {33 d2 48 8b c1 b9 08 00 00 00 3a db 74 90 01 01 8b c1 48 63 4c 24 90 01 01 48 8b 54 24 90 00 } //01 00 
		$a_03_2 = {0f b6 44 01 90 01 01 8b 4c 24 90 01 01 33 c8 66 3b ff 74 ca 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}