
rule Trojan_Win32_Vidar_MC_MTB{
	meta:
		description = "Trojan:Win32/Vidar.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc c1 e0 04 8b 4d 08 0f be 09 03 c1 89 45 fc 8b 45 fc 25 00 00 00 f0 89 45 f4 74 11 8b 45 f4 c1 e8 18 33 45 fc 25 ff ff ff 0f 89 45 fc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Vidar_MC_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 07 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 6a 0c b9 3c 08 45 00 e8 d1 1e 00 00 b9 3c 08 45 00 e8 57 13 00 00 68 30 4a 40 00 e8 94 } //3
		$a_01_1 = {2d 00 00 83 c4 04 5d c3 cc cc cc cc cc cc cc cc 53 8b dc 83 ec 08 83 e4 f8 83 c4 04 55 8b 6b 04 } //3
		$a_01_2 = {ab 2c 01 00 45 4e 4a 45 59 } //3
		$a_03_3 = {b9 48 08 45 00 e8 ?? ?? ?? ?? 8d 4d ff e8 ?? ?? ?? ?? 89 45 f8 c6 45 dc 21 c6 45 dd 32 c6 45 de 26 c6 45 df 6f c6 45 e0 54 } //1
		$a_01_4 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_6 = {43 00 61 00 6c 00 63 00 4d 00 6f 00 76 00 61 00 2e 00 65 00 78 00 65 00 } //1 CalcMova.exe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=13
 
}
rule Trojan_Win32_Vidar_MC_MTB_3{
	meta:
		description = "Trojan:Win32/Vidar.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0b 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 31 33 35 2e 31 38 31 2e 32 36 2e 31 38 33 } //4 ://135.181.26.183
		$a_01_1 = {5c 73 63 72 65 65 6e 73 68 6f 74 2e 6a 70 67 } //1 \screenshot.jpg
		$a_03_2 = {47 65 63 6b 6f 20 2f 20 [0-25] 20 46 69 72 65 66 6f 78 } //1
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 43 72 79 70 74 6f 67 72 61 70 68 79 } //1 SOFTWARE\Microsoft\Cryptography
		$a_01_4 = {45 6e 6b 72 79 70 74 } //1 Enkrypt
		$a_01_5 = {4f 70 65 72 61 20 57 61 6c 6c 65 74 } //1 Opera Wallet
		$a_01_6 = {45 78 6f 64 75 73 5c 65 78 6f 64 75 73 2e 77 61 6c 6c 65 74 } //1 Exodus\exodus.wallet
		$a_01_7 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 46 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //1 Select * From Win32_OperatingSystem
		$a_01_8 = {52 00 4f 00 4f 00 54 00 5c 00 43 00 49 00 4d 00 56 00 32 00 } //1 ROOT\CIMV2
		$a_01_9 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 46 00 72 00 6f 00 6d 00 20 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //1 Select * From AntiVirusProduct
		$a_01_10 = {72 00 6f 00 6f 00 74 00 5c 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 43 00 65 00 6e 00 74 00 65 00 72 00 32 00 } //1 root\SecurityCenter2
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=14
 
}