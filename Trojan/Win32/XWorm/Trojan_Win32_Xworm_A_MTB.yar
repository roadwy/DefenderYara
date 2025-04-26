
rule Trojan_Win32_Xworm_A_MTB{
	meta:
		description = "Trojan:Win32/Xworm.A!MTB,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {24 56 42 24 4c 6f 63 61 6c 5f 50 6f 72 74 } //1 $VB$Local_Port
		$a_01_1 = {24 56 42 24 4c 6f 63 61 6c 5f 48 6f 73 74 } //1 $VB$Local_Host
		$a_01_2 = {67 65 74 5f 4a 70 65 67 } //1 get_Jpeg
		$a_01_3 = {67 65 74 5f 53 65 72 76 69 63 65 50 61 63 6b } //1 get_ServicePack
		$a_01_4 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //1 Select * from AntivirusProduct
		$a_01_5 = {50 43 52 65 73 74 61 72 74 } //1 PCRestart
		$a_01_6 = {73 68 75 74 64 6f 77 6e 2e 65 78 65 20 2f 66 20 2f 72 20 2f 74 20 30 } //1 shutdown.exe /f /r /t 0
		$a_01_7 = {53 74 6f 70 52 65 70 6f 72 74 } //1 StopReport
		$a_01_8 = {53 74 6f 70 44 44 6f 73 } //1 StopDDos
		$a_01_9 = {73 65 6e 64 50 6c 75 67 69 6e } //1 sendPlugin
		$a_01_10 = {4f 66 66 6c 69 6e 65 4b 65 79 6c 6f 67 67 65 72 20 4e 6f 74 20 45 6e 61 62 6c 65 64 4f 66 66 6c 69 6e 65 4b 65 79 6c 6f 67 67 65 72 20 4e 6f 74 20 45 6e 61 62 6c 65 64 } //1 OfflineKeylogger Not EnabledOfflineKeylogger Not Enabled
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}