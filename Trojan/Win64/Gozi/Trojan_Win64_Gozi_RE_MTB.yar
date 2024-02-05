
rule Trojan_Win64_Gozi_RE_MTB{
	meta:
		description = "Trojan:Win64/Gozi.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 8b c5 ba 00 10 00 00 41 b9 01 00 00 00 44 2b c6 49 8b cf 41 81 e8 90 01 04 e8 90 01 04 8b 43 0c ff c6 2b 43 08 49 81 c7 00 10 00 00 03 43 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Gozi_RE_MTB_2{
	meta:
		description = "Trojan:Win64/Gozi.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 8b c5 ba 00 10 00 00 41 b9 01 00 00 00 44 2b c6 49 8b cf 41 81 e8 13 c8 47 7e e8 90 01 04 8b 43 0c ff c6 2b 43 08 49 81 c7 00 10 00 00 03 43 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}