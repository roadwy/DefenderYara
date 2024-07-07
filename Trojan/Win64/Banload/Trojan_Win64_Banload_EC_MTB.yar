
rule Trojan_Win64_Banload_EC_MTB{
	meta:
		description = "Trojan:Win64/Banload.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 11 00 00 "
		
	strings :
		$a_81_0 = {41 6e 74 69 43 68 65 61 74 2e 65 78 65 } //1 AntiCheat.exe
		$a_81_1 = {42 61 69 6c 65 79 2f 31 2e 30 } //1 Bailey/1.0
		$a_81_2 = {64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d } //1 discordapp.com
		$a_81_3 = {61 70 69 2f 77 65 62 68 6f 6f 6b 73 2f 31 32 30 34 32 32 30 33 38 32 30 39 34 31 36 38 31 34 35 2f 61 6e 70 6f 62 4c 73 4d 51 66 39 58 37 77 6a 43 77 56 52 33 77 69 46 65 71 7a 4d 4e 52 48 58 7a 30 37 51 75 62 4d 44 59 36 4c 6a 68 5a 53 47 37 61 70 76 51 55 55 4f 66 35 54 33 5f 5a 30 69 43 76 68 78 46 } //1 api/webhooks/1204220382094168145/anpobLsMQf9X7wjCwVR3wiFeqzMNRHXz07QubMDY6LjhZSG7apvQUUOf5T3_Z0iCvhxF
		$a_81_4 = {53 69 6e 69 73 74 65 72 } //1 Sinister
		$a_81_5 = {43 68 65 61 74 20 45 6e 67 69 6e 65 20 37 2e 35 } //1 Cheat Engine 7.5
		$a_81_6 = {78 36 34 64 62 67 } //1 x64dbg
		$a_81_7 = {46 69 6c 65 47 72 61 62 } //1 FileGrab
		$a_81_8 = {4e 69 67 67 65 72 } //1 Nigger
		$a_81_9 = {42 65 61 6d 6d 65 72 } //1 Beammer
		$a_81_10 = {50 72 6f 63 65 73 73 20 48 61 63 6b 65 72 } //1 Process Hacker
		$a_81_11 = {64 65 78 7a 75 6e 70 61 63 6b 65 72 } //1 dexzunpacker
		$a_81_12 = {54 4c 53 20 63 61 6c 6c 62 61 63 6b 3a 20 74 68 72 65 61 64 20 61 74 74 61 63 68 } //1 TLS callback: thread attach
		$a_81_13 = {54 4c 53 20 63 61 6c 6c 62 61 63 6b 3a 20 70 72 6f 63 65 73 73 20 61 74 74 61 63 68 } //1 TLS callback: process attach
		$a_81_14 = {54 4c 53 20 63 61 6c 6c 62 61 63 6b 3a 20 64 75 6d 6d 79 20 74 68 72 65 61 64 20 6c 61 75 6e 63 68 65 64 } //1 TLS callback: dummy thread launched
		$a_81_15 = {54 4c 53 43 61 6c 6c 62 61 63 6b 54 68 72 65 61 64 20 74 69 6d 65 6f 75 74 20 6f 6e 20 65 76 65 6e 74 20 63 72 65 61 74 69 6f 6e 2e } //1 TLSCallbackThread timeout on event creation.
		$a_81_16 = {41 6c 6c 20 73 65 65 6d 73 20 66 69 6e 65 20 66 6f 72 20 54 4c 53 43 61 6c 6c 62 61 63 6b 50 72 6f 63 65 73 73 2e } //1 All seems fine for TLSCallbackProcess.
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1) >=17
 
}