
rule Trojan_Win32_CobaltStrike_GIR_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.GIR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 81 e2 ff 00 00 00 8a 8c 15 fc fe ff ff 0f b6 c1 03 f8 81 e7 90 01 04 0f b6 84 3d fc fe ff ff 88 84 15 fc fe ff ff 88 8c 3d fc fe ff ff 0f b6 c9 81 e1 ff 00 00 80 79 90 01 01 49 81 c9 00 ff ff ff 41 0f b6 84 15 90 01 04 03 c8 81 e1 ff 00 00 80 79 90 01 01 49 81 c9 00 ff ff ff 41 0f b6 84 0d fc fe ff ff 30 04 33 46 81 fe 50 38 03 00 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}