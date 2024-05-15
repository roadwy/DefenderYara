
rule Trojan_Win64_CobaltStrike_U_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.U!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {48 8b 07 48 33 01 0f b6 57 90 01 01 32 51 90 01 01 0f b6 d2 48 09 c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}