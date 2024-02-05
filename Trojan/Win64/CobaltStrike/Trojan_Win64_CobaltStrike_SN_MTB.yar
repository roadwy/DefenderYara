
rule Trojan_Win64_CobaltStrike_SN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 cb 41 ff 40 90 01 01 81 f1 90 01 04 0f af c1 41 90 01 06 05 90 01 04 41 90 01 03 41 90 01 03 35 90 01 04 41 90 01 03 41 90 01 03 05 90 01 04 41 90 01 03 49 90 01 06 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}