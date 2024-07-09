
rule Trojan_Win32_Dridex_RAD_MTB{
	meta:
		description = "Trojan:Win32/Dridex.RAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 5f 33 00 00 85 c0 74 ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? eb ?? eb ?? 8b 55 ?? 03 55 ?? 8b 45 ?? 03 45 ?? 8b 4d ?? 8a 00 88 04 11 8b 4d ?? 83 c1 01 89 4d ?? eb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}