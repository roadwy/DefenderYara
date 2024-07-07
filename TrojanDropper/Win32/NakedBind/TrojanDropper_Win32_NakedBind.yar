
rule TrojanDropper_Win32_NakedBind{
	meta:
		description = "TrojanDropper:Win32/NakedBind,SIGNATURE_TYPE_PEHSTR_EXT,09 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {33 c0 64 8b 38 48 8b c8 f2 af af 8b 1f 66 33 db } //1
		$a_01_1 = {66 81 3b 4d 5a 74 08 81 eb 00 00 01 00 eb f1 bd } //1
		$a_01_2 = {40 00 ff 55 48 83 c7 07 ff 55 48 83 c7 08 ff 55 48 bb 90 01 02 40 00 be } //1
		$a_01_3 = {51 ff 55 24 89 45 5c } //1
		$a_01_4 = {ff ff eb ea 51 ff 55 0c } //1
		$a_01_5 = {84 c0 75 f2 c3 8b 53 3c 8b 74 1a 78 8d 74 1e 18 ad 91 ad } //1
		$a_01_6 = {c1 c2 03 32 10 40 80 38 00 75 f5 8b 04 24 83 04 24 02 8b fd } //1
		$a_01_7 = {39 17 75 13 0f b7 00 c1 e0 02 03 44 24 04 03 c3 8b 00 03 c3 ab eb 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}