
rule Trojan_Win32_CobaltStrike_YBN_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.YBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 8b 45 d8 0f af 45 ?? 29 c1 89 c8 01 c2 8b 45 d0 01 d0 0f b6 44 05 ?? 31 f0 88 03 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}