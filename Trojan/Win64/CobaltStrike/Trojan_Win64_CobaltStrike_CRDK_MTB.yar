
rule Trojan_Win64_CobaltStrike_CRDK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CRDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {4c 39 c2 73 90 01 01 44 8a 0c 10 44 8a 14 11 45 30 ca 44 88 14 10 44 88 0c 11 48 ff c2 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}