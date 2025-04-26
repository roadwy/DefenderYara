
rule Trojan_Win32_KeyLogger_BE_MTB{
	meta:
		description = "Trojan:Win32/KeyLogger.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 73 15 8b 55 08 03 55 fc 8a 02 32 45 10 8b 4d 08 03 4d fc 88 01 eb } //2
		$a_01_1 = {6a 04 68 00 10 00 00 8b 55 f4 52 6a 00 ff 15 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_Win32_KeyLogger_BE_MTB_2{
	meta:
		description = "Trojan:Win32/KeyLogger.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {10 8a 85 55 28 2a 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 21 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 43 6c 61 73 } //2
		$a_01_1 = {05 4f 9a c3 ec bd 05 f0 3e 8e 3a 4f ad 33 99 66 cf 11 b7 0c 00 aa 00 60 d3 93 46 6f 72 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}