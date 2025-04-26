
rule Trojan_Win64_CobaltStike_YBD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStike.YBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 03 b8 01 00 00 00 2b c1 01 43 18 8b 05 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 83 c0 fa 03 c1 48 63 8b ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 0f b6 43 } //11
	condition:
		((#a_03_0  & 1)*11) >=11
 
}