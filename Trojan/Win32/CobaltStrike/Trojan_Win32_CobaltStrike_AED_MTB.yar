
rule Trojan_Win32_CobaltStrike_AED_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.AED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c1 01 f9 89 f8 31 f0 89 4d e4 23 45 e4 89 c2 31 f2 8b 45 0c 83 c0 04 8b 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}