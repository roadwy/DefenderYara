
rule Trojan_Win64_CobaltStrike_DED_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 0f 45 c8 42 0f b6 04 19 30 42 ff 33 c0 49 83 f8 0c } //00 00 
	condition:
		any of ($a_*)
 
}