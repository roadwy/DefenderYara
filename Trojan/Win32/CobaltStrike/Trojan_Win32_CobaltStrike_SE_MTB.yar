
rule Trojan_Win32_CobaltStrike_SE_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 c1 ea 90 01 01 88 14 01 b8 90 01 04 2b 46 90 01 01 01 46 90 01 01 8b 86 90 01 04 33 86 90 01 04 33 46 90 01 01 ff 46 90 01 01 35 90 01 04 8b 4e 90 01 01 89 46 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}