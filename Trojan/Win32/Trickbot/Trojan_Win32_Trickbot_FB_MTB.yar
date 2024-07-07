
rule Trojan_Win32_Trickbot_FB_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.FB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 c2 81 c2 13 c6 85 71 83 ea 01 81 ea 13 c6 85 71 0f af c2 83 e0 01 83 f8 00 0f 94 c3 83 f9 0a 0f 9c c7 88 d8 20 f8 30 fb 08 d8 a8 01 } //1
		$a_01_1 = {81 ea 21 87 22 ee 83 ea 01 81 c2 21 87 22 ee 0f af c2 83 e0 01 83 f8 00 0f 94 c3 83 f9 0a 0f 9c c7 88 d8 34 ff 88 fc 80 f4 ff b1 01 80 f1 01 88 c5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}