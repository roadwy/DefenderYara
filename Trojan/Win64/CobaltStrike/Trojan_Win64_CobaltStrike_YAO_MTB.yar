
rule Trojan_Win64_CobaltStrike_YAO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {fe c3 8a 94 1d 90 01 04 02 c2 90 13 8a 8c 05 90 01 04 88 8c 1d 90 01 04 90 13 88 94 05 90 01 04 02 ca 8a 8c 0d 90 01 04 30 0e e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}