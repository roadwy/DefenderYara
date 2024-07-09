
rule TrojanDropper_Win32_Mader_gen_B{
	meta:
		description = "TrojanDropper:Win32/Mader.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff 10 7d 21 8b ?? ?? ?? ff ff 8b 84 ?? ?? ?? ff ff 2d ?? ?? ?? ?? 8b 8d ?? ?? ff ff 88 84 0d ?? ?? ff ff eb } //2
		$a_03_1 = {0f b6 4d fb 33 c1 90 09 1d 00 89 85 ?? ?? ff ff 8b ?? ?? ?? ff ff 3b ?? 10 7d ?? 8b ?? 08 03 ?? ?? ?? ff ff 0f b6 } //2
		$a_01_2 = {3e 56 6d 49 6d 67 44 65 73 63 72 69 70 74 6f 72 } //1 >VmImgDescriptor
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}