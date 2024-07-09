
rule Trojan_Win32_CobaltStrike_IF_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.IF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c2 83 e2 ?? 8a 14 11 8b 4d ?? 32 14 01 88 14 06 40 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}