
rule Trojan_Win32_TrickBot_VDSK_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.VDSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {0f b6 84 15 ec d1 ff ff 33 c1 8b 4d f4 88 84 0d ec d1 ff ff eb } //2
		$a_00_1 = {89 f8 b9 cd cc cc cc f7 e1 c1 ea 02 83 e2 fe 8d 2c 92 f7 dd 56 e8 } //1
		$a_02_2 = {83 c4 04 8a 84 2b ?? ?? ?? ?? 30 83 ?? ?? ?? ?? 56 e8 90 09 05 00 e8 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}