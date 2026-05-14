
rule Trojan_Win64_ClipBanker_MX_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {85 c0 75 0b 48 83 c3 08 48 3b df 75 e6 33 c0 48 8b 5c 24 30 48 83 c4 20 } //1
		$a_01_1 = {41 75 64 69 6f 48 65 6c 70 65 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 41 75 64 69 6f 48 65 6c 70 65 72 2e 70 64 62 } //1 AudioHelper\x64\Release\AudioHelper.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_ClipBanker_MX_MTB_2{
	meta:
		description = "Trojan:Win64/ClipBanker.MX!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {78 76 2d 63 6c 69 70 70 65 72 } //1 xv-clipper
		$a_01_1 = {6d 61 69 6e 2e 67 65 74 43 6c 69 70 41 64 64 72 65 73 73 65 73 } //1 main.getClipAddresses
		$a_01_2 = {24 47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 $GetClipboardData
		$a_01_3 = {72 75 6e 4d 75 74 65 78 43 68 65 63 6b } //1 runMutexCheck
		$a_01_4 = {54 65 6c 65 67 72 61 6d 50 61 79 6c 6f 61 64 } //1 TelegramPayload
		$a_01_5 = {53 65 6e 64 53 65 65 64 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //1 SendSeedNotification
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}