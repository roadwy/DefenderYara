
rule Trojan_Win32_Trickbot_RTA_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 bf ab 05 00 00 f7 ff 80 c2 3d 85 f6 76 90 01 01 8a 01 32 c2 02 c2 88 01 83 c1 01 83 ee 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_RTA_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 4c 68 b8 51 47 00 ff 75 90 01 01 ff 55 90 01 01 85 c0 74 90 01 01 8b 45 90 01 01 ff 30 50 ff 75 90 01 01 53 6a 01 53 ff 75 90 01 01 ff 55 90 01 01 85 c0 0f 95 c0 eb 90 01 01 32 c0 90 00 } //01 00 
		$a_01_1 = {6a 3c 43 2a 31 72 58 26 45 35 39 49 71 43 32 } //00 00  j<C*1rX&E59IqC2
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_RTA_MTB_3{
	meta:
		description = "Trojan:Win32/Trickbot.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e9 02 f3 ab 8b ca 83 e1 03 f3 aa 8d 45 90 01 01 89 5d 90 01 01 50 53 ff 75 90 01 01 6a 4c 68 90 01 04 ff 75 90 01 01 e8 90 01 04 85 c0 5f 74 90 01 01 8b 45 90 01 01 ff 30 50 ff 75 90 01 01 53 6a 01 53 ff 75 90 01 01 e8 90 01 04 85 c0 0f 95 c0 eb 90 01 01 32 c0 90 00 } //01 00 
		$a_01_1 = {79 33 66 70 23 3c 49 4e 36 5a 70 41 5e 29 54 } //00 00  y3fp#<IN6ZpA^)T
	condition:
		any of ($a_*)
 
}