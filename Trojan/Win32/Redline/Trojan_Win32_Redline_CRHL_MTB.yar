
rule Trojan_Win32_Redline_CRHL_MTB{
	meta:
		description = "Trojan:Win32/Redline.CRHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 3d f8 fe ff ff 88 84 35 f8 fe ff ff 88 8c 3d f8 fe ff ff 0f b6 84 35 f8 fe ff ff 8b 8d 88 fc ff ff 03 c2 0f b6 c0 0f b6 84 05 f8 fe ff ff 30 81 ?? ?? ?? ?? 41 89 8d 88 fc ff ff 81 f9 ?? ?? ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}