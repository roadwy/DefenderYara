
rule Trojan_Win32_CobaltStrike_PG_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 45 90 01 01 31 18 83 45 90 01 01 04 8b 45 90 01 01 83 c0 04 89 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}