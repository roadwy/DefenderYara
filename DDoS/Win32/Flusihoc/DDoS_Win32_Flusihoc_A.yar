
rule DDoS_Win32_Flusihoc_A{
	meta:
		description = "DDoS:Win32/Flusihoc.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 0c 00 00 "
		
	strings :
		$a_03_0 = {3c 7c 74 0f (3a|3c) ?? 74 0b ?? 88 01 8a 04 ?? 41 84 c0 75 ed } //2
		$a_01_1 = {3d 88 01 00 00 75 05 fe 06 fe 46 1e 3d 68 01 00 00 75 05 fe 06 fe 4e 17 83 f8 34 75 03 fe 4e 18 } //2
		$a_03_2 = {83 c6 04 83 c4 0c 81 ?? 90 00 81 ?? 2c 01 00 00 81 fe ?? ?? ?? ?? 7c } //2
		$a_01_3 = {25 73 7c 25 73 7c 25 73 7c 25 73 7c 25 73 65 6e 64 00 } //2 猥╼米猥╼米猥湥d
		$a_01_4 = {53 59 4e 5f 46 6c 6f 6f 64 00 } //1 奓彎汆潯d
		$a_01_5 = {55 44 50 5f 46 6c 6f 6f 64 00 } //1 䑕彐汆潯d
		$a_01_6 = {49 43 4d 50 5f 46 6c 6f 6f 64 00 } //1
		$a_01_7 = {54 43 50 5f 46 6c 6f 6f 64 00 } //1 䍔彐汆潯d
		$a_01_8 = {48 54 54 50 5f 46 6c 6f 6f 64 00 } //1
		$a_01_9 = {44 4e 53 5f 46 6c 6f 6f 64 00 } //1 乄当汆潯d
		$a_01_10 = {43 4f 4e 5f 46 6c 6f 6f 64 00 } //1 佃彎汆潯d
		$a_01_11 = {43 43 5f 46 6c 6f 6f 64 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=4
 
}