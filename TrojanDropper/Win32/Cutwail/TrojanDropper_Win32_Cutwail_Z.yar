
rule TrojanDropper_Win32_Cutwail_Z{
	meta:
		description = "TrojanDropper:Win32/Cutwail.Z,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b d8 c1 e3 03 81 c3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b e5 ff 15 ?? ?? ?? ?? c1 e0 11 2d ?? ?? ?? ?? 03 c3 } //1
		$a_03_1 = {03 45 fc 31 03 83 e9 [0-03] 7c 08 03 45 f8 83 c3 04 eb ?? 33 c0 8b 5d } //1
		$a_01_2 = {b9 2f 0a ab 3d 81 c1 ae c2 10 6d 8b 45 fc 83 c0 04 39 08 75 f9 50 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}