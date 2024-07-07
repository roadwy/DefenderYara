
rule Trojan_Win64_CobaltStrike_LT_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 b9 40 00 00 00 41 b8 00 30 00 00 ba 90 01 04 b9 00 00 00 00 48 8b 05 90 01 04 ff 90 00 } //1
		$a_03_1 = {0f b6 08 8b 85 90 01 04 48 98 0f b6 54 05 ba 8b 85 90 01 04 4c 63 c0 48 8b 85 90 01 04 4c 01 c0 31 ca 88 10 83 85 90 01 04 01 83 85 90 01 04 01 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}