
rule TrojanDropper_Win32_Dogrobot_C{
	meta:
		description = "TrojanDropper:Win32/Dogrobot.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {83 c0 01 83 c0 01 83 c0 01 83 c0 01 83 c0 01 61 60 b8 64 00 00 00 83 c0 01 83 c0 01 83 c0 01 } //1
		$a_02_1 = {57 6a 03 6a 01 6a 10 56 56 53 ff 15 ?? ?? ?? ?? 8b ?? ff 15 ?? ?? ?? ?? 3d 31 04 00 00 75 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}