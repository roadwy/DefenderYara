
rule Trojan_Win64_Rhadamanthys_RAZ_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.RAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {4d 8b f1 48 c1 ee 03 8d 7a 08 4c 2b f3 48 ff c6 48 8d 4c 24 60 4c 8b c7 48 8b d5 e8 90 01 04 4c 8b cb 4c 8b c5 33 d2 49 8b cd e8 90 01 04 48 8b cf 41 8a 04 1e 30 03 48 ff c3 48 ff c9 75 90 00 } //01 00 
		$a_03_1 = {4d 8b f1 48 c1 eb 03 bf 90 01 04 4c 2b f6 48 ff c3 48 8b d5 48 8b ce 4c 8b c7 48 2b d6 41 8a 04 0e 32 01 88 04 0a 48 ff c1 49 ff c8 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}