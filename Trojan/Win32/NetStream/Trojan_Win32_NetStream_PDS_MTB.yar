
rule Trojan_Win32_NetStream_PDS_MTB{
	meta:
		description = "Trojan:Win32/NetStream.PDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b d7 8b ca b8 05 00 00 00 03 c1 83 e8 05 89 45 fc a1 ?? ?? ?? ?? 8b 4d fc 89 08 } //2
		$a_02_1 = {8a 5c 05 f8 30 9c 3d ?? ?? ?? ?? 8b c6 83 e0 03 83 c6 06 8a 54 05 f8 30 94 3d ?? ?? ?? ?? 8d 41 ff 83 e0 03 83 e1 03 8a 44 05 f8 30 84 3d ?? ?? ?? ?? 8a 44 0d f8 30 84 3d ?? ?? ?? ?? 30 9c 3d } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}