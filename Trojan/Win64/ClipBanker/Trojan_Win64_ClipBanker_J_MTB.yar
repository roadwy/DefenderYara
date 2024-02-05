
rule Trojan_Win64_ClipBanker_J_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {48 89 4c 24 38 48 89 44 24 40 48 8d 44 24 38 48 89 44 24 60 c6 44 24 27 03 } //02 00 
		$a_01_1 = {48 89 44 24 48 48 89 5c 24 50 48 89 4c 24 58 48 89 7c 24 28 48 89 74 24 30 c6 44 24 27 01 48 8b 54 24 60 48 8b 02 } //00 00 
	condition:
		any of ($a_*)
 
}