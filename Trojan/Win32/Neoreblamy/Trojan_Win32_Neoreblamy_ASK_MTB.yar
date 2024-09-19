
rule Trojan_Win32_Neoreblamy_ASK_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ASK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 18 00 00 "
		
	strings :
		$a_01_0 = {62 6a 4a 6c 52 72 49 4e 41 74 6b 52 78 6d 6b 76 65 49 } //1 bjJlRrINAtkRxmkveI
		$a_01_1 = {55 43 41 68 74 4b 4c 55 78 5a 6f 47 4e 4e 61 6d 53 71 70 5a 65 6f 77 78 43 4b 44 4f 4a } //1 UCAhtKLUxZoGNNamSqpZeowxCKDOJ
		$a_01_2 = {64 4d 65 68 72 6c 71 52 45 68 76 61 56 73 4c 62 49 6f 6c 69 61 65 51 61 56 6e 66 75 4c 6e 58 4b 64 6b 67 4b 47 } //1 dMehrlqREhvaVsLbIoliaeQaVnfuLnXKdkgKG
		$a_01_3 = {70 79 79 77 73 63 7a 73 44 54 73 72 68 65 46 56 47 79 73 50 4a 6a 45 49 45 44 69 55 79 4b 46 6c 52 76 6e } //1 pyywsczsDTsrheFVGysPJjEIEDiUyKFlRvn
		$a_01_4 = {6d 7a 49 6b 73 6b 4a 70 76 57 75 42 4b 51 62 46 76 66 41 56 42 73 48 4c 75 6b 42 69 6e 75 48 75 76 50 49 59 67 6e 59 } //1 mzIkskJpvWuBKQbFvfAVBsHLukBinuHuvPIYgnY
		$a_01_5 = {54 79 50 49 6e 6c 77 48 49 48 56 58 68 72 73 62 66 74 61 43 79 4b 46 74 58 48 46 61 51 47 6b 66 76 65 52 4f 4e 62 4e 79 47 54 } //1 TyPInlwHIHVXhrsbftaCyKFtXHFaQGkfveRONbNyGT
		$a_01_6 = {70 78 6d 43 70 41 6d 59 62 61 79 6c 64 45 61 6c 49 49 57 6a 54 44 56 43 64 65 58 4c 55 74 4b 57 6e 44 4b 4f 74 } //1 pxmCpAmYbayldEalIIWjTDVCdeXLUtKWnDKOt
		$a_01_7 = {44 6e 73 4f 74 42 6d 42 50 51 4f 79 61 65 58 46 4e 47 51 62 62 76 47 63 6a 73 59 58 56 57 72 57 4c 59 } //1 DnsOtBmBPQOyaeXFNGQbbvGcjsYXVWrWLY
		$a_01_8 = {4e 68 74 77 79 72 70 7a 73 49 6e 6e 59 71 73 43 4d 64 48 59 53 78 57 43 6b 7a 6e 48 4c 6c } //1 NhtwyrpzsInnYqsCMdHYSxWCkznHLl
		$a_01_9 = {47 56 59 6c 75 67 78 50 6c 56 57 70 46 46 44 44 68 55 71 4e 45 70 45 50 4a 59 6b 59 49 78 70 56 71 59 } //1 GVYlugxPlVWpFFDDhUqNEpEPJYkYIxpVqY
		$a_01_10 = {4f 42 6e 43 61 73 76 50 49 77 78 57 4c 41 73 6d 54 71 4f 6a 44 52 66 4e 6f 55 57 65 68 42 41 62 51 77 48 4d } //1 OBnCasvPIwxWLAsmTqOjDRfNoUWehBAbQwHM
		$a_01_11 = {65 50 65 79 71 4b 73 73 75 4f 6f 58 79 53 79 63 71 4f 59 62 50 48 45 55 74 4f 65 6c 50 61 41 57 76 66 69 6e 69 43 67 } //1 ePeyqKssuOoXySycqOYbPHEUtOelPaAWvfiniCg
		$a_01_12 = {61 79 53 61 4e 45 4c 65 52 45 71 4a 55 6c 76 77 59 48 4b 66 4b 72 65 76 53 59 42 76 77 6b } //1 aySaNELeREqJUlvwYHKfKrevSYBvwk
		$a_01_13 = {45 4f 48 62 68 57 74 6a 73 43 46 71 51 48 50 50 56 70 76 58 4f 6b 62 4b 63 79 6b 4f 69 58 } //1 EOHbhWtjsCFqQHPPVpvXOkbKcykOiX
		$a_01_14 = {4a 67 61 53 65 72 66 47 67 59 5a 70 4a 6d 6c 63 6d 57 63 75 6a 51 58 4a 48 57 5a 6f 72 78 6e 59 73 5a 4b 79 70 } //1 JgaSerfGgYZpJmlcmWcujQXJHWZorxnYsZKyp
		$a_01_15 = {43 78 4f 75 7a 41 6f 53 75 63 67 47 67 6d 62 53 71 77 74 5a 6a 73 54 74 52 61 74 62 6f 4c 6f 73 58 4b 48 44 42 79 54 } //1 CxOuzAoSucgGgmbSqwtZjsTtRatboLosXKHDByT
		$a_01_16 = {47 46 64 70 6f 6d 48 51 5a 63 50 55 63 58 58 46 42 73 73 70 4c 52 79 4f 6d 7a 67 64 } //1 GFdpomHQZcPUcXXFBsspLRyOmzgd
		$a_01_17 = {71 74 69 52 4b 41 44 4e 72 4d 50 72 78 61 59 5a 75 51 53 4c 61 68 43 71 67 7a 49 6c 69 4e 62 58 4b 55 } //1 qtiRKADNrMPrxaYZuQSLahCqgzIliNbXKU
		$a_01_18 = {74 64 45 6e 78 41 4c 53 61 42 42 51 4e 4b 55 69 74 6d 72 68 6f 6c 73 62 70 7a 65 74 6d } //1 tdEnxALSaBBQNKUitmrholsbpzetm
		$a_01_19 = {4a 6c 54 67 73 53 73 45 44 4d 67 50 69 78 55 6e 62 6e 50 7a 6d 45 76 78 51 4f 70 46 53 } //1 JlTgsSsEDMgPixUnbnPzmEvxQOpFS
		$a_01_20 = {53 6d 61 4f 47 6f 61 63 47 6a 62 5a 4c 57 43 6e 76 4a 59 50 4d 4f 70 74 74 5a 69 74 6d 6a } //1 SmaOGoacGjbZLWCnvJYPMOpttZitmj
		$a_01_21 = {4b 7a 4c 66 54 6c 4f 54 67 6f 4c 4d 6c 61 49 42 43 48 57 6d 64 79 4b 79 6d 41 66 41 49 56 6d 6d 63 79 } //1 KzLfTlOTgoLMlaIBCHWmdyKymAfAIVmmcy
		$a_01_22 = {6d 72 62 42 67 54 68 74 65 53 56 46 59 52 58 49 51 59 56 6b 78 7a 6a 42 4e 50 67 68 56 45 51 6d 49 79 } //1 mrbBgThteSVFYRXIQYVkxzjBNPghVEQmIy
		$a_01_23 = {43 69 65 4b 77 51 6d 5a 7a 47 44 50 6e 44 49 6f 76 58 7a 41 59 72 4c 50 61 6c 62 4c 51 57 55 6c 63 50 74 79 } //1 CieKwQmZzGDPnDIovXzAYrLPalbLQWUlcPty
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1) >=4
 
}