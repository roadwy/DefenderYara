
rule Trojan_Win64_CobaltStrike_CBVC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CBVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4a 8d 14 07 49 ff c0 0f b6 04 13 f6 d0 88 02 49 81 f8 } //01 00 
		$a_01_1 = {80 34 39 bb 48 ff c1 48 81 f9 } //00 00 
	condition:
		any of ($a_*)
 
}