
rule Trojan_Win32_CobaltStrike_YAN_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.YAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 d1 03 fa 81 e7 ff 00 00 80 79 ?? 4f 81 cf 00 ff ff ff 47 0f b6 84 3d 7c fe ff ff 88 84 35 7c fe ff ff 88 8c 3d 7c fe ff ff 0f b6 84 35 7c fe ff ff 8b 8d 78 fd ff ff 03 c2 8b 95 74 fd ff ff 0f b6 c0 0f b6 84 05 7c fe ff ff 30 04 0a 42 89 95 74 fd ff ff 3b d3 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}