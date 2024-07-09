
rule Trojan_Win32_Azorult_GJ_MTB{
	meta:
		description = "Trojan:Win32/Azorult.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 ff 8d 77 01 8b c7 83 e0 03 8d 4e fe 8a 5c 05 f8 30 9c 3d ?? ?? ff ff 8b c6 83 e0 03 83 c6 06 8a 54 05 f8 30 94 3d ?? ?? ff ff 8d 41 ff 83 e0 03 83 e1 03 8a 44 05 f8 30 84 3d ?? ?? ff ff 8a 44 0d f8 30 84 3d ?? ?? ff ff 30 9c 3d ?? ?? ff ff 30 94 3d ?? ?? ff ff 83 c7 06 81 fe ?? ?? 00 00 72 a2 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}