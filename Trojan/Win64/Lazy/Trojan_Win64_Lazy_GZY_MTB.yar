
rule Trojan_Win64_Lazy_GZY_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {49 03 c6 4c 89 64 24 90 01 01 48 89 45 90 01 01 ff 15 90 01 04 48 8b 4c 24 90 01 01 48 8d 54 24 90 01 01 ff 15 90 01 04 48 8b 4c 24 90 01 01 ff 15 90 01 04 49 8b cd e8 90 00 } //05 00 
		$a_03_1 = {44 8b 03 8b 53 f8 4d 03 c5 44 8b 90 01 01 fc 49 03 d6 48 8b 4c 24 90 01 01 4c 89 64 24 90 01 01 ff 15 90 01 04 0f b7 46 90 01 01 48 8d 5b 90 01 01 ff c7 3b f8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}