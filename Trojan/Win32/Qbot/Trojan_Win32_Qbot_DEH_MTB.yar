
rule Trojan_Win32_Qbot_DEH_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {01 f9 81 e1 ff 00 00 00 8b 7c 24 34 8a 1c 0f 8b 4c 24 2c 81 e9 90 01 04 8b 7c 24 28 89 0c 24 8b 4c 24 0c 8a 3c 0f 8b 0c 24 89 4c 24 48 30 fb 8b 4c 24 24 8b 7c 24 0c 88 1c 39 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_DEH_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.DEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f af ca 89 4c 24 1c 8b 4c 24 14 8a 1c 01 8b 74 24 10 88 1c 06 8b 7c 24 1c 81 f7 90 02 08 89 7c 24 1c 31 ff b9 90 01 04 8b 54 24 08 29 d1 8b 54 24 0c 19 d7 89 7c 24 24 89 4c 24 20 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_DEH_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.DEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0c 00 00 "
		
	strings :
		$a_81_0 = {48 52 72 6b 69 57 66 6c 6f 75 } //1 HRrkiWflou
		$a_81_1 = {56 47 41 76 76 41 73 77 68 73 } //1 VGAvvAswhs
		$a_81_2 = {47 6d 5a 5a 46 79 70 6d 46 4f } //1 GmZZFypmFO
		$a_81_3 = {62 4c 4d 46 78 77 20 4d 76 42 } //1 bLMFxw MvB
		$a_81_4 = {45 59 6a 50 4f 5a 52 4a 51 78 } //1 EYjPOZRJQx
		$a_81_5 = {45 56 66 68 69 48 64 43 78 42 } //1 EVfhiHdCxB
		$a_81_6 = {43 7a 7a 6b 56 61 71 70 55 45 } //1 CzzkVaqpUE
		$a_81_7 = {64 4b 71 65 56 4e 64 4a 63 62 } //1 dKqeVNdJcb
		$a_81_8 = {55 48 57 54 49 55 78 47 64 78 } //1 UHWTIUxGdx
		$a_81_9 = {4d 62 57 43 7a 53 49 53 6b 72 } //1 MbWCzSISkr
		$a_81_10 = {78 4a 73 45 46 43 54 79 45 64 } //1 xJsEFCTyEd
		$a_81_11 = {75 55 53 58 4a 63 49 53 4f 74 } //1 uUSXJcISOt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=5
 
}