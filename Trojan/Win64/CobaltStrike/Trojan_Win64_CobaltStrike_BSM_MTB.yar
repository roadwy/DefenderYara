
rule Trojan_Win64_CobaltStrike_BSM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 98 48 8d 15 40 1a 00 00 0f b6 14 10 8b 85 fc 39 04 00 48 98 0f b6 44 05 c0 31 d0 8b 95 f8 39 04 00 48 63 d2 88 44 15 e0 83 85 fc 39 04 00 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}