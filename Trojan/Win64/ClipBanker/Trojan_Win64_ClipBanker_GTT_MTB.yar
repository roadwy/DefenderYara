
rule Trojan_Win64_ClipBanker_GTT_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {58 4d 52 62 6e 62 31 42 4e 42 } //2 XMRbnb1BNB
		$a_01_1 = {54 52 58 30 78 33 66 45 54 43 30 78 45 54 48 74 31 5a 45 43 62 63 31 31 33 42 54 43 2d 5f 54 4f 4e } //2 TRX0x3fETC0xETHt1ZECbc113BTC-_TON
		$a_01_2 = {62 69 74 63 6f 69 6e 63 61 73 68 7c 62 63 68 72 65 67 7c 62 63 68 74 65 73 74 } //2 bitcoincash|bchreg|bchtest
		$a_01_3 = {43 72 65 61 74 65 4d 75 74 65 78 } //1 CreateMutex
		$a_01_4 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
		$a_01_5 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 SetClipboardData
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}