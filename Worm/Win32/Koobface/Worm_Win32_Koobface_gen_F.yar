
rule Worm_Win32_Koobface_gen_F{
	meta:
		description = "Worm:Win32/Koobface.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_02_0 = {8d 85 38 ff ff ff c6 85 38 ff ff ff 6d 50 c6 85 39 ff ff ff 59 c6 85 3a ff ff ff 73 c6 85 3b ff ff ff 70 c6 85 3c ff ff ff 41 c6 85 3d ff ff ff 43 c6 85 3e ff ff ff 45 c6 85 3f ff ff ff 2e c6 85 40 ff ff ff 43 c6 85 41 ff ff ff 4f c6 85 42 ff ff ff 4d ff 15 ?? ?? ?? ?? 6a 63 8d 85 d4 fe ff ff 6a 00 50 e8 } //10
		$a_01_1 = {8d 4d fc 6a 00 51 ff d0 85 c0 74 0a f6 45 fc 07 74 04 b0 01 } //10
		$a_00_2 = {72 00 65 00 61 00 64 00 79 00 53 00 74 00 61 00 74 00 65 00 } //1 readyState
		$a_00_3 = {25 73 57 25 73 72 6f 73 25 73 6f 77 25 73 72 65 6e 74 56 65 72 25 73 75 6e } //1 %sW%sros%sow%srentVer%sun
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=22
 
}