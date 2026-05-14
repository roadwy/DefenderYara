
rule Trojan_Win32_Mikey_AD_MTB{
	meta:
		description = "Trojan:Win32/Mikey.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 01 3c 31 74 1b 3c 33 74 17 83 ff 04 72 50 8a 01 3c 62 75 4a 80 79 01 63 75 44 80 79 02 31 75 3e 33 d2 3c 62 0f 94 c2 8d 14 d5 22 00 00 00 3b fa 73 02 8b d7 33 f6 85 d2 74 18 0f b6 04 0e 6a 00 50 e8 4b ff ff ff 83 c4 08 85 c0 74 11 46 3b f2 72 e8 } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}