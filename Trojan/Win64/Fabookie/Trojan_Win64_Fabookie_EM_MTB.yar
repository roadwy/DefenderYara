
rule Trojan_Win64_Fabookie_EM_MTB{
	meta:
		description = "Trojan:Win64/Fabookie.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_01_0 = {48 63 d0 48 83 ec 06 48 8d 64 24 06 80 04 11 08 66 ff f1 48 83 ec 10 48 8d 64 24 02 48 8d 64 24 10 83 c0 01 41 3b c0 e8 00 00 00 00 44 89 74 24 02 } //00 00 
	condition:
		any of ($a_*)
 
}