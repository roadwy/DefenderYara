
rule TrojanDropper_Win32_Mader_gen_B{
	meta:
		description = "TrojanDropper:Win32/Mader.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {ff 10 7d 21 8b 90 01 03 ff ff 8b 84 90 01 03 ff ff 2d 90 01 04 8b 8d 90 01 02 ff ff 88 84 0d 90 01 02 ff ff eb 90 00 } //02 00 
		$a_03_1 = {0f b6 4d fb 33 c1 90 09 1d 00 89 85 90 01 02 ff ff 8b 90 01 03 ff ff 3b 90 01 01 10 7d 90 01 01 8b 90 01 01 08 03 90 01 03 ff ff 0f b6 90 00 } //01 00 
		$a_01_2 = {3e 56 6d 49 6d 67 44 65 73 63 72 69 70 74 6f 72 } //00 00  >VmImgDescriptor
	condition:
		any of ($a_*)
 
}