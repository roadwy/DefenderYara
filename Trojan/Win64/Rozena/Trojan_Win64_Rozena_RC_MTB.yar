
rule Trojan_Win64_Rozena_RC_MTB{
	meta:
		description = "Trojan:Win64/Rozena.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {df c6 cb b6 c7 85 90 01 02 00 00 57 35 9c 21 c7 85 90 01 02 00 00 78 9f 93 38 c7 85 90 01 02 00 00 1e d4 01 58 c7 85 90 01 02 00 00 24 c9 71 7f c7 85 90 01 02 00 00 ad 56 74 8a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}