
rule Trojan_WinNT_Zegost_B_rootkit{
	meta:
		description = "Trojan:WinNT/Zegost.B!rootkit,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 09 00 00 "
		
	strings :
		$a_01_0 = {eb 09 8b 45 a8 83 c0 01 89 45 a8 81 7d a8 49 01 00 00 0f 83 08 01 00 00 8b 4d a8 6b c9 3c 81 c1 00 f0 01 00 51 8d 55 ac 52 ff 15 } //5
		$a_01_1 = {75 df 8b 95 54 ff ff ff 2b 95 50 ff ff ff d1 fa 89 95 48 ff ff ff 83 bd 48 ff ff ff 0a 76 25 8b 45 a8 6b c0 3c 05 } //5
		$a_01_2 = {68 4f 46 4e 49 68 cc a8 3b 00 6a 00 ff } //5
		$a_01_3 = {5c 00 61 00 6e 00 74 00 69 00 76 00 73 00 68 00 6c 00 70 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //5 \antivshlp32.dll
		$a_01_4 = {74 00 6d 00 70 00 72 00 6f 00 78 00 79 00 2e 00 65 00 78 00 65 00 } //1 tmproxy.exe
		$a_01_5 = {76 00 69 00 72 00 2e 00 65 00 78 00 65 00 } //1 vir.exe
		$a_01_6 = {7a 00 6f 00 6e 00 65 00 61 00 6c 00 61 00 72 00 6d 00 2e 00 65 00 78 00 65 00 } //1 zonealarm.exe
		$a_01_7 = {61 00 76 00 67 00 6e 00 74 00 2e 00 65 00 78 00 65 00 } //1 avgnt.exe
		$a_01_8 = {6b 00 61 00 73 00 6d 00 61 00 69 00 6e 00 2e 00 65 00 78 00 65 00 } //1 kasmain.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=17
 
}