
rule Trojan_Win64_CobaltStrike_A_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //1 Go build ID:
		$a_81_1 = {4e 66 70 74 56 55 68 74 38 66 58 41 65 62 54 4d 50 73 76 63 } //1 NfptVUht8fXAebTMPsvc
		$a_81_2 = {4e 6c 6f 6f 6f 33 79 50 54 4d 72 6b 44 63 55 44 48 73 49 57 } //1 Nlooo3yPTMrkDcUDHsIW
		$a_81_3 = {67 69 74 68 75 62 2e 63 6f 6d 2f 6d 69 74 72 65 2f 67 6f 63 61 74 2f } //1 github.com/mitre/gocat/
		$a_81_4 = {65 76 61 6c 75 61 74 65 57 61 74 63 68 64 6f 67 } //1 evaluateWatchdog
		$a_81_5 = {6b 65 79 20 65 78 70 61 6e 73 69 6f 6e } //1 key expansion
		$a_81_6 = {6d 61 73 74 65 72 20 73 65 63 72 65 74 } //1 master secret
		$a_81_7 = {63 6c 69 65 6e 74 20 66 69 6e 69 73 68 65 64 } //1 client finished
		$a_81_8 = {73 65 72 76 65 72 20 66 69 6e 69 73 68 65 64 } //1 server finished
		$a_81_9 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b } //1 expand 32-byte kexpand 32-byte k
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}