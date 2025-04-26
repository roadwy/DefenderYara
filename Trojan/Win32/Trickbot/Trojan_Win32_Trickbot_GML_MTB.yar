
rule Trojan_Win32_Trickbot_GML_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.GML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 03 f0 83 c6 20 8b 3e 83 ee 0c 8b 06 03 7d fc 89 45 f4 83 ee 14 33 d2 8b 5d 0c c3 } //10
		$a_01_1 = {8b d0 8b 5d f0 b8 00 00 00 00 42 8b 0a 40 81 e1 ff 00 00 00 75 f4 } //5
		$a_01_2 = {83 c3 01 8b 03 41 38 d0 75 f6 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=20
 
}