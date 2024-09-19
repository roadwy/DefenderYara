
rule Trojan_Win32_CobaltStrike_YBO_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.YBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 06 2d fa e1 15 00 01 86 20 01 00 00 8b 46 44 8b d3 33 86 20 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}