
rule Trojan_Win32_NetStream_DSK_MTB{
	meta:
		description = "Trojan:Win32/NetStream.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d6 8b ca b8 89 dc 00 00 03 c1 2d 89 dc 00 00 89 45 fc a1 ?? ?? ?? ?? 8b 4d fc 89 08 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}
rule Trojan_Win32_NetStream_DSK_MTB_2{
	meta:
		description = "Trojan:Win32/NetStream.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 75 f8 33 f2 b8 26 09 00 00 b8 26 09 00 00 b8 26 09 00 00 b8 26 09 00 00 b8 26 09 00 00 } //2
		$a_02_1 = {b8 26 09 00 00 8b d6 8b ca b8 89 dc 00 00 03 c1 2d 89 dc 00 00 89 45 fc a1 ?? ?? ?? ?? 8b 4d fc 89 08 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}