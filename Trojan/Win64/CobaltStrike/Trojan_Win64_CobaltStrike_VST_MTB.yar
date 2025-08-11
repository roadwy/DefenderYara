
rule Trojan_Win64_CobaltStrike_VST_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.VST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 98 0f b6 84 05 90 00 00 00 88 85 96 01 00 00 48 8b 95 c0 01 00 00 48 8b 85 98 01 00 00 48 01 d0 0f b6 00 48 8b 8d c8 01 00 00 48 8b 95 98 01 00 00 48 01 ca 32 85 96 01 00 00 88 02 48 83 85 98 01 00 00 01 48 8b 85 98 01 00 00 48 3b 85 d0 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}