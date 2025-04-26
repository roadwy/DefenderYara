
rule Trojan_Win32_Tibs_S{
	meta:
		description = "Trojan:Win32/Tibs.S,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {8d 6c 24 00 83 c4 fc } //1
		$a_01_1 = {8d 5d 0c 8b 5c 23 00 8d 1c 03 8d 7d 08 8b 7c 27 00 8d 75 08 8b 74 26 00 } //1
		$a_01_2 = {f7 d2 ff c2 29 d1 8d 04 01 50 8f 06 e8 } //1
		$a_01_3 = {c3 66 a5 66 a5 60 29 f3 61 } //1
		$a_01_4 = {8d 4d fc 8b 4c 21 00 c9 c2 0c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}