
rule Trojan_Win32_Predator_GJ_MTB{
	meta:
		description = "Trojan:Win32/Predator.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 5c 24 10 90 0a 50 00 8b 4b 04 90 02 04 89 4c 24 04 90 02 04 8b 4b 08 90 02 04 89 4c 24 08 90 02 04 83 c3 0c 90 02 04 89 5c 24 0c 90 02 04 33 db 8b 54 24 0c 90 02 04 8b 12 33 d3 90 02 04 3b 54 24 08 90 02 04 74 90 01 01 90 02 04 43 90 02 04 90 02 04 eb 90 01 01 89 5c 24 10 90 00 } //01 00 
		$a_02_1 = {ff e2 8b 04 24 90 0a 50 00 31 1c 0a 90 02 04 3b 4c 24 04 90 02 04 7d 90 01 01 90 02 04 90 02 04 83 c1 04 90 02 04 eb 90 01 01 8b e5 90 02 04 5d 90 02 04 5b 90 02 04 ff e2 8b 04 24 90 02 04 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}