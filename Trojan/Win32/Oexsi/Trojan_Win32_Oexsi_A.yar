
rule Trojan_Win32_Oexsi_A{
	meta:
		description = "Trojan:Win32/Oexsi.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 6c 10 40 00 50 e8 24 00 00 00 8d 85 fc fe ff ff 68 60 10 40 00 50 e8 13 00 00 00 83 c4 10 8d 85 fc fe ff ff } //1
		$a_01_1 = {33 c9 39 4c 24 0c 7e 19 8b 44 24 08 56 8b 74 24 08 8a 16 32 d1 88 10 40 46 41 3b 4c 24 10 7c f1 5e } //1
		$a_03_2 = {57 ff d6 59 85 c0 59 75 27 39 45 10 6a 21 74 0a ff 75 0c 68 ?? ?? 40 00 eb 08 68 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}