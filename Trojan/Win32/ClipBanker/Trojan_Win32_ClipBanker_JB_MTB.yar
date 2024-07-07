
rule Trojan_Win32_ClipBanker_JB_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.JB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {55 52 54 45 57 4e 44 30 51 } //1 URTEWND0Q
		$a_81_1 = {4f 70 65 6e 43 6c 69 70 62 6f 61 72 64 } //1 OpenClipboard
		$a_81_2 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
		$a_81_3 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 SetClipboardData
		$a_81_4 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //1 CreateMutexA
		$a_81_5 = {44 65 46 6d 47 4d 41 52 48 7a 32 59 64 68 54 4a 33 52 4d 53 79 59 48 37 75 4e 53 6e 35 52 72 64 4b } //1 DeFmGMARHz2YdhTJ3RMSyYH7uNSn5RrdK
		$a_81_6 = {33 47 46 56 68 70 6d 6b 6d 6d 52 6e 73 39 36 75 35 36 78 6b 4e 43 73 38 48 51 74 4d 61 4a 47 4e 44 } //1 3GFVhpmkmmRns96u56xkNCs8HQtMaJGND
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule Trojan_Win32_ClipBanker_JB_MTB_2{
	meta:
		description = "Trojan:Win32/ClipBanker.JB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {34 54 59 41 74 43 46 54 58 43 36 6f 44 77 42 33 69 79 4c 35 76 78 6e 46 57 71 47 74 77 50 59 } //1 4TYAtCFTXC6oDwB3iyL5vxnFWqGtwPY
	condition:
		((#a_01_0  & 1)*1) >=1
 
}