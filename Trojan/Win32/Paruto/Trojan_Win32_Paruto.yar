
rule Trojan_Win32_Paruto{
	meta:
		description = "Trojan:Win32/Paruto,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a c2 8a 4c 14 ?? f6 ea 04 03 84 c9 74 0a 3a c8 74 06 32 c8 88 4c 14 ?? 42 81 fa } //1
		$a_03_1 = {6a 02 50 ff ?? 81 fb 02 01 00 00 74 ?? 81 fd 02 01 00 00 74 ?? 81 ff 02 01 00 00 74 ?? a1 ?? ?? ?? ?? 5d 85 c0 74 ?? 6a ff 50 ff d6 } //1
		$a_03_2 = {25 03 00 00 80 79 ?? 48 83 c8 fc 40 40 8d 04 40 8d 04 80 8d 04 80 8d 04 80 8d 04 80 c1 e0 04 } //1
		$a_03_3 = {83 c9 ff 33 c0 f2 ae f7 d1 49 83 f9 40 0f 83 ?? ?? 00 00 85 d2 0f 8e ?? ?? 00 00 81 fa ff ff 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=100
 
}