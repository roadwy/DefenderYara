
rule Trojan_Win32_CobaltStrike_NVN_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.NVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {56 6a 04 68 00 30 00 00 57 50 ff 55 } //2
		$a_01_1 = {66 0f 3a 0f d9 0c 66 0f 7f 1f 66 0f 6f e0 66 0f 3a 0f c2 0c 66 0f 7f 47 10 66 0f 6f cd 66 0f 3a 0f ec 0c 66 0f 7f 6f 20 8d 7f 30 73 b7 } //2
		$a_01_2 = {31 2e 64 6c 6c } //1 1.dll
		$a_01_3 = {61 76 5f 66 72 61 6d 65 5f 67 65 74 5f 63 68 61 6e 6e 65 6c 73 } //1 av_frame_get_channels
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}