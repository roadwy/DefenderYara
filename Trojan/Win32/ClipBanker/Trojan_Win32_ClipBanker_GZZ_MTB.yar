
rule Trojan_Win32_ClipBanker_GZZ_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {5b b3 cb 64 0a 6d ef 30 76 01 fb b5 8a 3d 27 19 0e e9 } //5
		$a_01_1 = {48 19 5a aa 31 36 12 58 3e 5f 1c b4 2f 50 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}
rule Trojan_Win32_ClipBanker_GZZ_MTB_2{
	meta:
		description = "Trojan:Win32/ClipBanker.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 ff 15 90 01 04 85 c0 74 90 01 01 6a 0d ff 15 90 01 04 89 45 e4 8b 45 e4 50 ff 15 90 01 04 89 45 e0 8b 4d e0 51 90 00 } //10
		$a_01_1 = {43 72 65 61 74 65 4d 75 74 65 78 } //1 CreateMutex
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}
rule Trojan_Win32_ClipBanker_GZZ_MTB_3{
	meta:
		description = "Trojan:Win32/ClipBanker.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b f8 8d 44 24 90 01 01 50 57 ff 15 90 01 04 ff 15 90 01 04 57 6a 01 ff 15 90 01 04 56 ff d3 8d 4c 24 90 01 01 51 8d 4c 24 90 01 01 e8 90 01 04 ff 15 90 00 } //10
		$a_03_1 = {8b f8 8b 54 24 90 01 01 52 57 ff 15 90 01 04 ff 15 90 01 04 57 6a 01 ff 15 90 01 04 56 ff 15 90 01 04 6a 00 ff 15 90 01 04 33 f6 ff 15 90 00 } //10
		$a_01_2 = {74 72 6f 6e 2e 6d 68 78 69 65 79 69 2e 63 6f 6d } //1 tron.mhxieyi.com
		$a_01_3 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}