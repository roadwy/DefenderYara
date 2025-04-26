
rule Trojan_Win32_CobaltStrike_GTT_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 04 c8 0f b7 cb 0b c1 0f b6 4c 24 ?? 0b c2 33 d2 f7 f1 8b 4c 24 ?? 31 04 37 8d 43 ?? 0f b7 c0 03 c0 5f 5e } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}