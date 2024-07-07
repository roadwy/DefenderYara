
rule TrojanDropper_Win32_Dogkild_B{
	meta:
		description = "TrojanDropper:Win32/Dogkild.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 64 72 69 76 65 72 73 5c 67 6d 2e 64 6c 73 00 } //1
		$a_01_1 = {5c 5c 2e 5c 70 63 69 64 75 6d 70 00 } //1 屜尮捰摩浵p
		$a_01_2 = {63 6d 64 20 2f 63 20 6e 65 74 20 73 74 6f 70 20 77 73 63 73 76 63 00 } //1
		$a_03_3 = {83 c4 14 56 ff d3 83 f8 02 74 08 56 ff d3 83 f8 03 90 13 d1 6c 24 90 01 01 47 83 ff 28 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2) >=4
 
}