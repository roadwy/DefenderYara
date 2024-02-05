
rule Trojan_Win64_Wingo_psyA_MTB{
	meta:
		description = "Trojan:Win64/Wingo.psyA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {49 3b 66 10 76 2b 48 83 ec 20 48 89 6c 24 18 48 8d 6c 24 18 48 8b 10 48 89 c3 b9 01 00 00 00 48 89 d0 e8 19 f6 ff ff 48 8b 6c 24 18 48 83 c4 20 c3 48 89 44 24 08 e8 25 06 05 00 48 8b 44 24 08 eb be } //00 00 
	condition:
		any of ($a_*)
 
}