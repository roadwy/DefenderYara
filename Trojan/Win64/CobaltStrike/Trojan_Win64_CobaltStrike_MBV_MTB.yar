
rule Trojan_Win64_CobaltStrike_MBV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff c0 89 44 24 54 8b 44 24 50 39 44 24 ?? 73 20 48 63 44 24 ?? 48 8b 4c 24 58 0f be 04 01 83 f0 45 48 63 4c 24 54 48 8b ?? 24 58 88 04 0a eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}