
rule TrojanDropper_Win32_Finkmilt_B{
	meta:
		description = "TrojanDropper:Win32/Finkmilt.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {74 0d 8b f8 57 e8 90 01 04 89 45 14 eb 02 eb 06 46 83 fe 64 76 d6 90 00 } //1
		$a_01_1 = {fc 33 c0 b9 ff ff ff ff f2 ae 38 07 75 de } //1
		$a_01_2 = {ff 4d 08 ff 75 08 e8 c1 ff ff ff c9 c2 04 00 } //1
		$a_01_3 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 35 } //1 \drivers\etc\host5
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}