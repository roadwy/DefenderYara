
rule Trojan_Win64_CobaltStrike_SPR_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {48 83 f8 64 4d 8d 40 01 49 0f 44 c3 41 ff c2 0f b6 4c 04 30 48 ff c0 41 30 48 ff 49 63 ca 48 81 f9 } //00 00 
	condition:
		any of ($a_*)
 
}