
rule TrojanDropper_Win32_Agent_DL{
	meta:
		description = "TrojanDropper:Win32/Agent.DL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {80 3c 30 2e 74 0b 90 8a 4c 30 ff 48 80 f9 2e 75 f6 } //1
		$a_03_1 = {68 e9 03 00 00 68 90 03 01 01 ea ed 03 00 00 56 e8 90 01 02 ff ff 83 c4 10 68 04 01 00 00 90 00 } //1
		$a_00_2 = {3c 69 66 72 61 6d 65 20 73 72 63 3d 27 } //1 <iframe src='
		$a_00_3 = {2d 69 64 78 20 30 20 2d 69 70 20 25 73 2d 25 73 } //1 -idx 0 -ip %s-%s
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}