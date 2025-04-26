
rule TrojanDropper_Win32_Genasom_B{
	meta:
		description = "TrojanDropper:Win32/Genasom.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b8 2e 65 78 65 [0-03] e8 ?? ?? ff ff 6a 00 6a 00 6a 02 6a 00 6a 01 68 00 00 00 40 } //1
		$a_03_1 = {83 c0 04 c1 ?? 0d 3d ?? ?? 00 00 72 e8 } //1
		$a_01_2 = {74 dc 00 00 00 83 c4 04 b8 2e 74 6d 70 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}