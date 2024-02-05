
rule Trojan_Win32_Emotet_GB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2b c8 03 0d 90 01 04 03 0d 90 01 04 03 0d 90 01 04 2b 0d 90 01 04 a1 90 01 04 0f af 05 90 01 04 2b c8 2b 0d 90 01 04 8b 45 08 0f b6 0c 08 8b 45 0c 0f b6 14 10 33 d1 a1 90 01 04 0f af 05 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 0f af 0d 90 01 04 0f af 0d 90 01 04 8b 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_GB_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 17 14 78 72 89 90 02 03 e8 90 02 04 68 db 49 35 93 89 90 02 03 e8 90 02 04 68 ce 08 01 4e 89 90 02 03 e8 90 02 04 68 ab 5e c3 4d 8b 90 01 01 e8 90 02 04 68 94 24 8e 94 89 90 02 03 e8 90 02 04 68 a3 ca 26 af 8b 90 01 01 e8 90 02 04 68 a7 91 44 c9 8b 90 01 01 e8 90 00 } //01 00 
		$a_02_1 = {33 c4 89 44 90 02 19 f3 90 01 01 68 15 5b 04 71 90 02 02 e8 90 02 04 68 20 e6 3c 0b 8b 90 01 01 e8 90 02 04 68 73 e1 88 9f 8b 90 01 01 e8 90 02 04 68 20 f6 3c 14 8b 90 01 01 e8 90 00 } //01 00 
		$a_02_2 = {51 52 6a 00 6a 01 6a 00 50 ff 90 02 03 5f f7 d8 5e 1b c0 23 90 02 03 5d 5b 83 c4 90 01 01 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}