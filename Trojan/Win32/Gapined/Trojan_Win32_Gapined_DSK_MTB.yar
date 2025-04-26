
rule Trojan_Win32_Gapined_DSK_MTB{
	meta:
		description = "Trojan:Win32/Gapined.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {33 c0 30 84 05 f0 fe ff ff 40 3b c7 7c 90 09 06 00 ff 15 } //2
		$a_02_1 = {8b 54 24 10 8b c7 c1 e8 05 03 44 24 ?? 03 cb 03 d7 33 ca 90 09 04 00 8b 4c 24 } //2
		$a_02_2 = {8b c1 c1 e8 02 24 3f c0 e1 06 0a c1 88 82 ?? ?? ?? ?? 83 c6 02 42 83 fe 1e 0f 82 } //2
		$a_00_3 = {8b 44 24 14 8a 0c 50 8a 14 1f 32 d1 88 14 1f } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2+(#a_00_3  & 1)*2) >=2
 
}