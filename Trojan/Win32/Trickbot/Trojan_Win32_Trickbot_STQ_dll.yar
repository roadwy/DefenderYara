
rule Trojan_Win32_Trickbot_STQ_dll{
	meta:
		description = "Trojan:Win32/Trickbot.STQ!dll,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 57 8b f2 8b f9 33 d2 6a 7c 68 e6 b7 a2 2c 42 e8 0f 2a 00 00 59 59 85 c0 74 06 56 57 ff d0 eb 02 } //1
		$a_01_1 = {b1 31 c7 85 ec fd ff ff 31 45 54 42 c7 85 f0 fd ff ff 45 6e 55 41 33 c0 c7 85 f4 fd ff ff 5e 42 45 00 30 8c 05 ed fd ff ff 40 83 f8 0a 73 08 8a 8d ec fd ff ff eb eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}