
rule Trojan_Win64_CobaltStrike_K_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {44 30 04 07 48 ff c0 49 39 c7 } //00 00 
	condition:
		any of ($a_*)
 
}