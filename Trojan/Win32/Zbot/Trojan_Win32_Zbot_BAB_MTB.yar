
rule Trojan_Win32_Zbot_BAB_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 30 5f d3 cf 68 7d 26 80 60 5a 03 54 24 0c 31 d7 89 3e 81 e1 00 00 00 00 f7 df 29 f9 f7 df c1 e9 03 85 ed 0f } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Zbot_BAB_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 54 00 65 00 6d 00 70 00 31 00 5f 00 56 00 6f 00 69 00 63 00 65 00 4d 00 65 00 73 00 73 00 61 00 67 00 65 00 2e 00 7a 00 69 00 70 00 5c 00 56 00 6f 00 69 00 63 00 65 00 4d 00 65 00 73 00 73 00 61 00 67 00 65 00 2e 00 65 00 78 00 65 00 } //1 AppData\Local\Temp\Temp1_VoiceMessage.zip\VoiceMessage.exe
		$a_01_1 = {43 00 3a 00 5c 00 66 00 42 00 79 00 50 00 44 00 6b 00 31 00 73 00 2e 00 65 00 78 00 65 00 } //1 C:\fByPDk1s.exe
		$a_01_2 = {43 00 3a 00 5c 00 42 00 57 00 48 00 72 00 74 00 4a 00 55 00 51 00 2e 00 65 00 78 00 65 00 } //1 C:\BWHrtJUQ.exe
		$a_01_3 = {43 00 3a 00 5c 00 47 00 65 00 57 00 70 00 4c 00 37 00 75 00 54 00 2e 00 65 00 78 00 65 00 } //1 C:\GeWpL7uT.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}