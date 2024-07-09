
rule TrojanDropper_Win32_Small_OT{
	meta:
		description = "TrojanDropper:Win32/Small.OT,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 85 c0 fe ff ff 40 89 85 c0 fe ff ff 8b 85 c0 fe ff ff 3b 45 e4 73 3b 8b 85 c0 fe ff ff 69 c0 ?? ?? ?? ?? 0f af 85 c0 fe ff ff 8b 8d c0 fe ff ff 69 c9 ?? ?? ?? ?? 03 c8 8b 45 e8 03 85 c0 fe ff ff 8a 00 32 c1 8b 4d e8 03 8d c0 fe ff ff 88 01 eb ad ff 75 e8 e8 ?? ?? ?? ?? 59 89 85 c4 fe ff ff 83 bd c4 fe ff ff 00 75 04 33 c0 eb 4b 68 ?? ?? ?? ?? ff b5 c4 fe ff ff e8 ?? ?? ?? ?? 59 59 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}