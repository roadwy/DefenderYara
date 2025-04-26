
rule Trojan_Win32_CobaltStrike_NAX_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.NAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {43 8a 84 1d f0 fe ff ff 88 84 3d f0 fe ff ff 88 8c 1d f0 fe ff ff 0f b6 84 3d f0 fe ff ff 8b 8d 3c fd ff ff 03 c2 8b 95 64 fd ff ff 0f b6 c0 8a 84 05 f0 fe ff ff 30 04 11 41 89 8d ?? ?? ?? ?? 3b ce 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}