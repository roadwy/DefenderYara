
rule Trojan_Win64_Tedy_ALAB_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ALAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {43 6c 69 70 62 6f 61 72 64 20 72 65 70 6c 61 63 65 72 3a 20 73 74 61 72 74 65 64 } //1 Clipboard replacer: started
		$a_81_1 = {41 4d 53 49 3a 20 62 79 70 61 73 73 65 64 } //1 AMSI: bypassed
		$a_81_2 = {43 6f 72 65 4d 61 69 6e 3a 20 73 61 6e 64 62 6f 78 20 63 68 65 63 6b 20 70 61 73 73 65 64 } //1 CoreMain: sandbox check passed
		$a_81_3 = {6e 74 64 6c 6c 20 75 6e 68 6f 6f 6b 65 64 20 28 63 6c 65 61 6e 20 63 6f 70 79 29 } //1 ntdll unhooked (clean copy)
		$a_81_4 = {65 76 61 73 69 6f 6e 20 69 6e 69 74 20 64 6f 6e 65 } //1 evasion init done
		$a_81_5 = {43 6f 6c 6c 65 63 74 69 6e 67 20 54 65 6c 65 67 72 61 6d 20 64 61 74 61 20 28 6d 61 69 6e 20 74 68 72 65 61 64 29 } //1 Collecting Telegram data (main thread)
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}