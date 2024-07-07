
rule Trojan_BAT_AgentTesla_N_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {06 13 04 7e 90 01 03 04 16 7e 90 01 03 04 a2 7e 90 01 03 04 17 7e 90 01 03 04 a2 7e 90 01 03 04 18 72 90 01 04 a2 14 d0 90 01 03 01 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_N_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {45 6e 61 62 6c 65 46 6f 63 75 73 54 72 61 63 6b 69 6e 67 } //3 EnableFocusTracking
		$a_81_1 = {53 79 73 74 65 6d 2e 43 6f 64 65 44 6f 6d 2e 43 6f 6d 70 69 6c 65 72 } //3 System.CodeDom.Compiler
		$a_81_2 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //3 System.Security.Cryptography
		$a_81_3 = {57 70 66 54 6f 75 63 68 4b 65 79 62 6f 61 72 64 } //3 WpfTouchKeyboard
		$a_81_4 = {53 65 72 76 69 63 65 48 75 62 2e 48 6f 73 74 } //3 ServiceHub.Host
		$a_81_5 = {32 2e 34 2e 32 32 37 2e 32 30 32 30 } //3 2.4.227.2020
		$a_81_6 = {32 2e 34 2e 32 32 37 2b 65 34 30 37 36 61 36 65 37 64 2e 52 52 } //3 2.4.227+e4076a6e7d.RR
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}
rule Trojan_BAT_AgentTesla_N_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {41 65 65 65 65 } //1 Aeeee
		$a_01_1 = {52 00 4d 00 51 00 59 00 4b 00 71 00 5a 00 72 00 4c 00 38 00 4a 00 67 00 70 00 77 00 48 00 34 00 68 00 30 00 59 00 70 00 77 00 } //1 RMQYKqZrL8JgpwH4h0Ypw
		$a_01_2 = {32 00 79 00 4d 00 37 00 66 00 6b 00 74 00 42 00 58 00 36 00 53 00 64 00 65 00 47 00 64 00 76 00 65 00 64 00 4a 00 39 00 56 00 6a 00 36 00 53 00 74 00 69 00 31 00 74 00 63 00 52 00 43 00 43 00 34 00 73 00 55 00 53 00 51 00 58 00 43 00 78 00 53 00 34 00 } //1 2yM7fktBX6SdeGdvedJ9Vj6Sti1tcRCC4sUSQXCxS4
		$a_01_3 = {53 00 63 00 72 00 69 00 70 00 74 00 73 00 } //1 Scripts
		$a_81_4 = {4c 6f 61 64 46 72 6f 6d 58 4d 4c 53 74 72 69 6e 67 } //1 LoadFromXMLString
		$a_01_5 = {41 6e 63 68 6f 72 53 74 79 6c 65 73 } //1 AnchorStyles
		$a_01_6 = {41 00 6c 00 69 00 63 00 69 00 75 00 6d 00 32 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Alicium2.Properties.Resources
		$a_01_7 = {57 65 62 42 72 6f 77 73 65 72 } //1 WebBrowser
		$a_01_8 = {56 00 65 00 72 00 64 00 61 00 6e 00 61 00 } //1 Verdana
		$a_01_9 = {50 6f 73 74 54 65 78 74 } //1 PostText
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_81_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}
rule Trojan_BAT_AgentTesla_N_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.N!MTB,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 00 74 00 61 00 72 00 74 00 47 00 61 00 6d 00 65 00 } //1 StartGame
		$a_01_1 = {47 00 61 00 6d 00 65 00 4f 00 76 00 65 00 72 00 } //1 GameOver
		$a_01_2 = {52 65 76 65 72 73 65 00 43 6f 6e 76 65 72 74 00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //10 敒敶獲e潃癮牥t牆浯慂敳㐶瑓楲杮
		$a_01_3 = {54 65 74 72 69 73 2e 44 65 73 6b 74 6f 70 2e 47 61 6d 65 4f 76 65 72 } //1 Tetris.Desktop.GameOver
		$a_01_4 = {47 00 41 00 4d 00 45 00 5f 00 4f 00 56 00 45 00 52 00 5f 00 4c 00 41 00 59 00 45 00 52 00 } //1 GAME_OVER_LAYER
		$a_01_5 = {00 52 61 74 65 00 } //1 刀瑡e
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=12
 
}