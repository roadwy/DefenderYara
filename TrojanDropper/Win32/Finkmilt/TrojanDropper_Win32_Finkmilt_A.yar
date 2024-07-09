
rule TrojanDropper_Win32_Finkmilt_A{
	meta:
		description = "TrojanDropper:Win32/Finkmilt.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 02 6a 00 6a 03 68 00 00 00 40 ff 75 08 e8 ?? ?? ?? ?? 89 45 fc 40 75 05 5b c9 c2 0c 00 ff 75 10 ff 75 0c ff 75 fc } //1
		$a_02_1 = {c7 85 d8 fe ff ff 28 01 00 00 6a 00 6a 02 e8 ?? ?? ?? ?? 89 85 d4 fe ff ff 8d 85 d8 fe ff ff 50 ff b5 d4 fe ff ff e8 ?? ?? ?? ?? 0b c0 74 3b bf } //1
		$a_02_2 = {6a 00 6a 00 6a 00 6a 00 6a 00 8d 15 ?? ?? ?? ?? 52 6a 00 6a 01 6a 01 6a 10 8d 15 ?? ?? ?? ?? 52 52 56 ff d0 85 c0 } //1
		$a_00_3 = {5c 64 66 72 74 69 2e 73 79 73 } //1 \dfrti.sys
		$a_00_4 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 35 } //1 \drivers\etc\host5
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}