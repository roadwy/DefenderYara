
rule Ransom_Win64_BQTLock_AMTB{
	meta:
		description = "Ransom:Win64/BQTLock!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_80_0 = {7b 20 22 75 73 65 72 6e 61 6d 65 22 3a 20 22 42 51 54 4c 6f 63 6b 20 42 6f 74 22 2c 20 22 65 6d 62 65 64 73 22 3a 20 5b 7b 20 22 74 69 74 6c 65 22 3a 20 22 49 6e 66 65 63 74 69 6f 6e 20 52 65 70 6f 72 74 22 2c 20 22 64 65 73 63 72 69 70 74 69 6f 6e 22 3a 20 22 41 20 6e 65 77 20 73 79 73 74 65 6d 20 68 61 73 20 62 65 65 6e 20 69 6e 66 65 63 74 65 64 } //{ "username": "BQTLock Bot", "embeds": [{ "title": "Infection Report", "description": "A new system has been infected  2
		$a_80_1 = {75 73 65 72 6e 61 6d 65 22 3a 20 22 42 51 54 4c 6f 63 6b 20 42 6f 74 22 2c 20 22 65 6d 62 65 64 73 22 3a 20 5b 7b 20 22 74 69 74 6c 65 22 3a 20 22 45 6e 63 72 79 70 74 69 6f 6e 20 43 6f 6d 70 6c 65 74 65 } //username": "BQTLock Bot", "embeds": [{ "title": "Encryption Complete  2
		$a_80_2 = {42 51 54 4c 6f 63 6b 20 50 61 79 6c 6f 61 64 20 66 69 6e 69 73 68 65 64 20 69 6e 69 74 69 61 6c 20 65 78 65 63 75 74 69 6f 6e 2e 20 45 6e 74 65 72 69 6e 67 20 70 65 72 73 69 73 74 65 6e 74 20 43 32 } //BQTLock Payload finished initial execution. Entering persistent C2  2
		$a_80_3 = {5c 43 24 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 62 71 74 5f 70 61 79 6c 6f 61 64 2e 65 78 65 } //\C$\Windows\Temp\bqt_payload.exe  2
		$a_80_4 = {64 65 66 65 6e 64 65 72 2e 65 78 65 } //defender.exe  1
		$a_80_5 = {6b 61 73 70 65 72 73 6b 79 2e 65 78 65 } //kaspersky.exe  1
		$a_80_6 = {6d 63 61 66 65 65 2e 65 78 65 } //mcafee.exe  1
		$a_80_7 = {73 6f 70 68 6f 73 2e 65 78 65 } //sophos.exe  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=12
 
}