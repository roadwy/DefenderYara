
rule Trojan_Win32_CobaltStrike_SIH_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.SIH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 94 c1 83 c7 04 03 d1 89 4d ec 8b 4d e8 89 54 8e 08 02 cb 0f b6 c9 02 c1 02 45 f0 0f b6 c0 0f b6 4c 86 08 30 4f fe } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}