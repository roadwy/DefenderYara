
rule Trojan_Win32_DarkComet_ADK_MTB{
	meta:
		description = "Trojan:Win32/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 6a 00 53 68 4c 28 1c 13 6a 00 6a 00 e8 dd 4f f8 ff db 6d e8 d8 25 24 2b 1c 13 db 7d e8 9b db 6d e8 d8 1d 1c 2b 1c 13 9b df e0 9e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_DarkComet_ADK_MTB_2{
	meta:
		description = "Trojan:Win32/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b ee 33 eb 23 e9 33 ee 03 fd 03 c7 8b f8 c1 e7 0c c1 e8 14 0b f8 03 f9 8b c7 8b 7a 08 03 3d 98 17 49 00 8b eb 33 e9 23 e8 33 eb 03 fd 03 f7 8b fe c1 e7 11 c1 ee 0f 0b fe 03 f8 8b f7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_DarkComet_ADK_MTB_3{
	meta:
		description = "Trojan:Win32/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 6a 00 68 00 04 00 00 8d 84 24 78 02 00 00 50 ff 74 24 } //2
		$a_01_1 = {48 6f 6f 6b 20 70 72 6f 63 65 64 75 72 65 20 68 61 73 20 62 65 65 6e 20 69 6e 73 74 61 6c 6c 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 Hook procedure has been installed successfully
		$a_01_2 = {4b 65 79 6c 6f 67 67 65 72 20 69 73 20 75 70 20 61 6e 64 20 72 75 6e 6e 69 6e 67 } //1 Keylogger is up and running
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_Win32_DarkComet_ADK_MTB_4{
	meta:
		description = "Trojan:Win32/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 4d cc 8d 45 d0 ba 2c 4e 48 00 e8 ?? ?? ?? ?? 8b 45 d0 e8 ?? ?? ?? ?? eb 20 8d 45 c4 } //2
		$a_01_1 = {44 44 4f 53 48 54 54 50 46 4c 4f 4f 44 } //1 DDOSHTTPFLOOD
		$a_01_2 = {42 54 52 45 53 55 4c 54 55 44 50 20 46 6c 6f 6f 64 7c 55 44 50 20 46 6c 6f 6f 64 20 74 61 73 6b 20 66 69 6e 69 73 68 65 64 } //1 BTRESULTUDP Flood|UDP Flood task finished
		$a_01_3 = {42 54 52 45 53 55 4c 54 53 79 6e 20 46 6c 6f 6f 64 7c 53 79 6e 20 74 61 73 6b 20 66 69 6e 69 73 68 65 64 } //1 BTRESULTSyn Flood|Syn task finished
		$a_01_4 = {42 54 52 45 53 55 4c 54 48 54 54 50 20 46 6c 6f 6f 64 7c 48 74 74 70 20 46 6c 6f 6f 64 20 74 61 73 6b 20 66 69 6e 69 73 68 65 64 } //1 BTRESULTHTTP Flood|Http Flood task finished
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}