
rule Trojan_Win64_CobaltStrike_BT_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 04 00 88 04 0a c7 84 24 [0-04] 01 00 00 00 b8 01 00 00 00 48 6b c0 00 c6 84 04 [0-04] 65 b8 01 00 00 00 48 6b c0 01 c6 84 04 [0-04] 72 b8 01 00 00 00 48 6b c0 02 c6 84 04 [0-04] 72 b8 01 00 00 00 48 6b c0 03 48 89 84 24 [0-04] 48 83 bc 24 [0-04] 0a 73 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}