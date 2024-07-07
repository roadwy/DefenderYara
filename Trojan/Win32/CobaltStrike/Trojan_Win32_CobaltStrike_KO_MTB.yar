
rule Trojan_Win32_CobaltStrike_KO_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.KO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c2 83 e2 90 01 01 8a 14 11 8b 4d 90 01 01 32 14 01 88 14 03 40 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}