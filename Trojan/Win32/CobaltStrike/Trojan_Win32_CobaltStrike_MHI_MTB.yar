
rule Trojan_Win32_CobaltStrike_MHI_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.MHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 75 c8 8b 7d cc 29 f7 89 d8 31 d2 f7 f7 0f b6 14 16 32 14 19 88 95 ?? ?? ?? ?? 8b 45 d8 3b 45 dc 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}