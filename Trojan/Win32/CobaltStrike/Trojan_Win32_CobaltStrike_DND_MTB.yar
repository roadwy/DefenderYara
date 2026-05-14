
rule Trojan_Win32_CobaltStrike_DND_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.DND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 5d 14 8b 04 1a 31 04 11 83 c2 04 3b 56 04 7c f2 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}