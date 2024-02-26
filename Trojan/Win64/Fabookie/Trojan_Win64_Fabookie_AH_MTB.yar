
rule Trojan_Win64_Fabookie_AH_MTB{
	meta:
		description = "Trojan:Win64/Fabookie.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 48 ff c0 48 83 e9 01 75 ba } //01 00 
		$a_01_1 = {80 00 1a eb 38 } //00 00 
	condition:
		any of ($a_*)
 
}