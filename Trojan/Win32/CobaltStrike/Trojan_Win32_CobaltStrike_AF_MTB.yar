
rule Trojan_Win32_CobaltStrike_AF_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 0f b7 01 33 d2 66 2b 90 01 05 33 d2 66 f7 90 01 05 33 d2 88 06 33 d2 46 33 d2 43 33 d2 83 c1 02 33 90 01 01 3b 90 01 01 7c 90 01 02 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}