
rule Trojan_Win32_Zbot_AN_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 13 32 c8 40 88 0a 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 42 83 ee 01 75 } //2
		$a_01_1 = {49 68 71 5f 7b 4a 54 51 57 74 57 4f 51 41 45 4f 4c 49 } //2 Ihq_{JTQWtWOQAEOLI
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}