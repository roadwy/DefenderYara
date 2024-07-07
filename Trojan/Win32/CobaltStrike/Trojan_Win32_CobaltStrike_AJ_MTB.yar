
rule Trojan_Win32_CobaltStrike_AJ_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 14 08 8b d3 ff 46 40 8b 86 d4 00 00 00 48 c1 ea 08 01 86 e4 00 00 00 a1 90 01 04 8b 48 40 8b 46 74 88 14 01 a1 90 01 04 ff 40 40 8b 90 02 05 0f 90 02 06 89 86 b8 00 00 00 a1 90 01 04 8b 4e 74 88 1c 08 a1 90 01 04 ff 05 90 01 04 8b 00 01 86 b8 00 00 00 81 ff 90 01 04 0f 8c 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}