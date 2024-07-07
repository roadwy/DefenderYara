
rule Trojan_Win32_CobaltStrike_KJ_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.KJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 83 f0 90 01 01 25 90 01 04 21 f9 09 f2 89 55 90 01 01 09 c8 89 45 90 01 01 8b 4d 90 01 01 8b 45 90 01 01 31 c8 88 45 90 01 01 8b 45 90 01 01 8a 4d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}