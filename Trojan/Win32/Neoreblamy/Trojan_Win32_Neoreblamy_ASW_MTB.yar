
rule Trojan_Win32_Neoreblamy_ASW_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 10 00 00 "
		
	strings :
		$a_01_0 = {43 62 6b 6a 6c 4f 78 4e 4b 52 6f 56 51 4b 4f 50 6b 47 47 78 59 4a 5a 77 41 56 79 55 53 44 } //1 CbkjlOxNKRoVQKOPkGGxYJZwAVyUSD
		$a_01_1 = {77 61 53 6a 5a 4e 70 66 61 71 70 67 55 6d 57 65 4f 5a 52 66 45 77 6b 5a 64 6e 52 42 41 79 } //1 waSjZNpfaqpgUmWeOZRfEwkZdnRBAy
		$a_01_2 = {6c 4b 58 69 4d 71 66 56 7a 50 4c 70 43 56 74 61 44 79 65 77 70 4f 6e 78 45 6e 51 4b 61 4f 6f 63 71 75 } //1 lKXiMqfVzPLpCVtaDyewpOnxEnQKaOocqu
		$a_01_3 = {78 68 6b 4f 63 6a 45 64 51 47 43 6d 63 43 6b 4d 73 57 44 6b 6d 72 41 57 55 } //1 xhkOcjEdQGCmcCkMsWDkmrAWU
		$a_01_4 = {70 4a 51 4d 4f 61 62 43 78 73 65 41 4c 56 4d 45 75 58 6a 71 47 54 7a 41 7a 50 45 65 42 67 } //1 pJQMOabCxseALVMEuXjqGTzAzPEeBg
		$a_01_5 = {62 65 71 4c 52 56 76 7a 41 4c 63 50 63 69 6b 5a 79 68 54 64 7a 79 42 71 50 76 4d 4e } //1 beqLRVvzALcPcikZyhTdzyBqPvMN
		$a_01_6 = {73 41 53 53 4d 63 7a 7a 50 57 4f 4e 62 42 77 6c 64 56 6b 7a 70 6f 5a 42 73 71 46 78 } //1 sASSMczzPWONbBwldVkzpoZBsqFx
		$a_01_7 = {66 49 59 72 7a 63 61 61 66 62 66 55 52 73 64 47 78 64 46 42 67 46 4c 77 53 65 46 41 46 65 77 73 79 44 } //1 fIYrzcaafbfURsdGxdFBgFLwSeFAFewsyD
		$a_01_8 = {76 6d 70 65 55 6b 5a 6a 59 78 4d 57 6e 52 6c 55 57 62 78 54 4c 6c 70 42 6e 74 47 6e 47 7a } //1 vmpeUkZjYxMWnRlUWbxTLlpBntGnGz
		$a_01_9 = {41 65 49 69 72 43 4c 61 55 79 4f 51 6d 6e 52 55 65 47 65 51 47 57 52 6f 55 65 6d 58 } //1 AeIirCLaUyOQmnRUeGeQGWRoUemX
		$a_01_10 = {7a 65 6a 54 46 46 59 6c 5a 65 6a 68 52 57 68 47 57 4a 52 58 43 6e 58 6e 67 76 57 53 47 64 66 6a 52 75 } //1 zejTFFYlZejhRWhGWJRXCnXngvWSGdfjRu
		$a_01_11 = {6f 74 65 66 49 6e 59 73 63 4a 7a 6d 46 58 62 4e 49 5a 52 69 4c 70 73 4d 6f 51 44 49 55 61 79 70 48 43 4b 65 6f 62 41 42 79 66 6f 6d 46 6b 4b 7a 62 52 6e 61 79 48 58 77 4c 53 59 62 52 4e 44 4e 77 75 54 7a 77 53 47 4b 45 4a 67 55 58 72 57 7a 5a 4c 72 7a 76 6c 65 65 74 } //1 otefInYscJzmFXbNIZRiLpsMoQDIUaypHCKeobAByfomFkKzbRnayHXwLSYbRNDNwuTzwSGKEJgUXrWzZLrzvleet
		$a_01_12 = {69 75 57 54 58 6d 74 69 4f 62 65 4a 70 79 52 4a 41 77 56 73 55 6f 72 4d 51 4d 61 63 75 73 } //1 iuWTXmtiObeJpyRJAwVsUorMQMacus
		$a_01_13 = {56 77 68 56 62 6b 4b 46 45 4b 65 63 52 54 78 6d 78 45 79 51 41 6f 6e 6d 71 52 7a 57 } //1 VwhVbkKFEKecRTxmxEyQAonmqRzW
		$a_01_14 = {5a 49 5a 48 55 77 41 47 51 53 78 63 52 71 7a 6a 61 53 77 70 54 78 46 7a 5a 4a 4b 6a 78 52 } //1 ZIZHUwAGQSxcRqzjaSwpTxFzZJKjxR
		$a_01_15 = {63 78 43 78 62 67 4d 48 41 7a 6f 6c 50 6d 62 71 65 56 69 64 45 64 61 69 4b 6b 62 4b 4f 4b 61 7a 6e 48 } //1 cxCxbgMHAzolPmbqeVidEdaiKkbKOKaznH
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=4
 
}