
rule Trojan_Win64_CobaltStrike_CBYC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CBYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 0f b6 44 05 d0 83 f0 90 01 01 89 c2 8b 85 90 01 04 48 98 88 54 05 d0 83 85 90 01 04 01 8b 85 90 01 04 3d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}