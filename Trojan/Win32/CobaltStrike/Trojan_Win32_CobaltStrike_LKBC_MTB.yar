
rule Trojan_Win32_CobaltStrike_LKBC_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.LKBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 68 ?? ?? 03 00 8b 85 ?? ?? ?? ?? 05 ?? ?? 03 00 50 68 ?? ?? 04 00 68 00 ?? ?? ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}