
rule Backdoor_Win64_ValleyRAT_GFH_MTB{
	meta:
		description = "Backdoor:Win64/ValleyRAT.GFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {25 50 72 6f 67 72 61 6d 44 61 74 61 25 5c 56 65 6e 6c 6e 6b } //%ProgramData%\Venlnk  1
		$a_80_1 = {5c 76 65 6e 53 75 63 63 65 73 73 2e 69 6e 69 } //\venSuccess.ini  1
		$a_80_2 = {5c 76 65 6e 77 69 6e 2e 6c 6f 63 6b } //\venwin.lock  1
		$a_80_3 = {55 53 44 54 20 68 69 6a 61 63 6b 20 73 74 61 72 74 65 64 } //USDT hijack started  1
		$a_01_4 = {73 68 75 74 64 6f 77 6e 20 2f 73 20 2f 66 20 2f 74 20 30 } //1 shutdown /s /f /t 0
		$a_80_5 = {5c 44 69 73 70 6c 61 79 53 65 73 73 69 6f 6e 43 6f 6e 74 61 69 6e 65 72 73 2e 6c 6f 67 } //\DisplaySessionContainers.log  1
		$a_80_6 = {45 6e 61 62 6c 65 4f 66 66 6c 69 6e 65 4b 65 79 62 6f 61 72 64 } //EnableOfflineKeyboard  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_01_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}