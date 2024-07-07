
rule Trojan_Win32_Qbot_AI_MTB{
	meta:
		description = "Trojan:Win32/Qbot.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 05 60 1a 00 10 90 02 04 89 45 f0 0f b6 0d 60 1a 00 10 8b 55 f0 2b d1 89 55 f0 0f b6 05 60 1a 00 10 33 45 f0 89 45 f0 90 00 } //2
		$a_01_1 = {89 45 f0 0f b6 0d 60 1a 00 10 33 4d f0 89 4d f0 0f b6 15 60 1a 00 10 8b 45 f0 2b c2 89 45 f0 0f b6 0d 60 1a 00 10 } //2
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}