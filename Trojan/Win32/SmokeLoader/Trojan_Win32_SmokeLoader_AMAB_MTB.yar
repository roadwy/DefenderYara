
rule Trojan_Win32_SmokeLoader_AMAB_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {1b 27 f9 45 37 3b 3e 00 b7 76 59 9c 78 9c ec 99 0c 83 0c 76 b7 44 e4 34 4f 30 0c 8b b1 85 0d 0d a7 c9 cb d0 f3 5d a5 39 4b 32 } //1
		$a_01_1 = {6b b5 e0 8b 1c 24 83 c4 04 eb 0a 4c 81 eb 06 32 00 00 eb 05 28 eb f5 4c 28 74 08 75 06 c9 9f 88 54 50 84 83 ec 04 c7 04 24 30 00 00 00 } //1
		$a_01_2 = {4b 42 5f 2f 59 42 5d 4e 58 4b 2f 59 42 42 4a 42 4c 2f 59 4d 40 57 48 5a 2f 59 4d 40 57 5c 49 2f 59 4d 40 57 42 40 2f 59 4d 40 57 59 46 2f 59 4d 40 57 4b 46 2f 59 46 40 5c 4a 5d 2f 2f 71 70 } //1 KB_/YB]NXK/YBBJBL/YM@WHZ/YM@W\I/YM@WB@/YM@WYF/YM@WKF/YF@\J]//qp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}