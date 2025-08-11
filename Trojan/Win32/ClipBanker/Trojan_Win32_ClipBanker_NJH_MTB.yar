
rule Trojan_Win32_ClipBanker_NJH_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.NJH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_81_0 = {31 32 31 3e 31 47 31 52 31 5c 31 62 31 68 31 6e 31 } //2 121>1G1R1\1b1h1n1
		$a_81_1 = {47 65 74 43 6c 69 70 62 6f 61 72 64 53 65 71 75 65 6e 63 65 4e 75 6d 62 65 72 } //1 GetClipboardSequenceNumber
		$a_81_2 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
		$a_81_3 = {47 6c 6f 62 61 6c 55 6e 6c 6f 63 6b } //1 GlobalUnlock
		$a_01_4 = {01 d8 89 d1 21 f1 09 d6 0f af f1 01 c6 89 f0 83 e0 fc 89 f1 83 e1 02 89 f2 83 ca 02 0f af d1 83 f1 02 0f af c8 01 ca } //1
		$a_01_5 = {89 c1 83 c9 01 21 d1 83 f0 01 8d 1c 48 89 de 83 e6 02 89 f2 83 f2 02 89 54 24 04 89 f5 } //1
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}