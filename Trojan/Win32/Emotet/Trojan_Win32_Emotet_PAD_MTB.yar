
rule Trojan_Win32_Emotet_PAD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 0f b6 1a 8b cf 66 d3 e3 42 66 f7 d3 0f b7 cb 8b d9 c1 eb 08 88 18 88 48 01 03 c6 ff 8d } //5
		$a_03_1 = {42 45 41 55 52 45 47 41 52 44 5c 50 69 63 74 75 72 65 73 5c [0-10] 5c 57 6f 72 6b 65 72 54 68 72 65 61 64 73 5c [0-15] 5c 57 6f 72 6b 65 72 54 68 72 65 61 64 73 2e 70 64 62 } //5
		$a_00_2 = {4c 6f 63 6b 57 69 6e 64 6f 77 55 70 64 61 74 65 } //1 LockWindowUpdate
		$a_00_3 = {4e 6f 4e 65 74 43 6f 6e 6e 65 63 74 44 69 73 63 6f 6e 6e 65 63 74 } //1 NoNetConnectDisconnect
		$a_01_4 = {52 65 63 65 6e 74 44 6f 63 73 48 69 73 74 6f 72 79 } //1 RecentDocsHistory
		$a_01_5 = {4c 6f 63 6b 46 69 6c 65 } //1 LockFile
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=14
 
}