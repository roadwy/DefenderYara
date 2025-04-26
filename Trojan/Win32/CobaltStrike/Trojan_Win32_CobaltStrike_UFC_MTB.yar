
rule Trojan_Win32_CobaltStrike_UFC_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.UFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {46 0f b6 84 34 70 01 00 00 88 84 14 ?? ?? ?? ?? 88 8c 34 70 01 00 00 0f b6 84 14 70 01 00 00 0f b6 c9 03 c8 0f b6 c1 8b 8c 24 88 00 00 00 0f b6 84 04 70 01 00 00 30 04 39 47 3b bc 24 a8 00 00 00 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}