
rule Trojan_Win32_CobaltStrike_MP_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7c 24 18 8b 4c 24 14 83 c7 14 41 89 7c 24 18 3b 4c 24 24 89 4c 24 14 8b 4c 24 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_CobaltStrike_MP_MTB_2{
	meta:
		description = "Trojan:Win32/CobaltStrike.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 6d fc 8a f1 88 4d ff 8a 48 fe 43 32 ca 88 48 0e 8a 48 ff 32 4d fe 88 48 0f 8a 08 32 cd 88 48 10 8a 48 01 32 ce 88 48 11 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_CobaltStrike_MP_MTB_3{
	meta:
		description = "Trojan:Win32/CobaltStrike.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_81_0 = {73 68 65 6c 6c 63 6f 64 65 6c 6f 61 64 69 6e 67 2f 63 68 65 63 6b 53 61 6e 64 62 6f 78 2e 74 69 6d 65 53 6c 65 65 70 } //1 shellcodeloading/checkSandbox.timeSleep
		$a_81_1 = {73 68 65 6c 6c 63 6f 64 65 6c 6f 61 64 69 6e 67 2f 63 68 65 63 6b 53 61 6e 64 62 6f 78 2e 70 68 79 73 69 63 61 6c 4d 65 6d 6f 72 79 } //1 shellcodeloading/checkSandbox.physicalMemory
		$a_81_2 = {73 68 65 6c 6c 63 6f 64 65 6c 6f 61 64 69 6e 67 2f 63 68 65 63 6b 53 61 6e 64 62 6f 78 2e 6e 75 6d 62 65 72 4f 66 43 50 55 } //1 shellcodeloading/checkSandbox.numberOfCPU
		$a_81_3 = {73 79 6e 63 2e 28 2a 4d 75 74 65 78 29 2e 4c 6f 63 6b } //1 sync.(*Mutex).Lock
		$a_81_4 = {63 72 79 70 74 6f 2f 63 69 70 68 65 72 2e 78 6f 72 42 79 74 65 73 } //1 crypto/cipher.xorBytes
		$a_81_5 = {73 68 65 6c 6c 63 6f 64 65 6c 6f 61 64 69 6e 67 2f 61 65 73 2e 41 65 73 44 65 63 72 79 70 74 } //1 shellcodeloading/aes.AesDecrypt
		$a_81_6 = {47 6f 20 62 75 69 6c 64 69 6e 66 } //1 Go buildinf
		$a_81_7 = {72 75 6e 74 69 6d 65 2e 69 6e 6a 65 63 74 67 6c 69 73 74 } //1 runtime.injectglist
		$a_81_8 = {73 79 6e 63 2e 28 2a 4d 75 74 65 78 29 2e 6c 6f 63 6b 53 6c 6f 77 } //1 sync.(*Mutex).lockSlow
		$a_81_9 = {73 79 6e 63 2e 28 2a 65 6e 74 72 79 29 2e 6c 6f 61 64 } //1 sync.(*entry).load
		$a_81_10 = {73 68 65 6c 6c 63 6f 64 65 6c 6f 61 64 69 6e 67 2f 63 68 65 63 6b 53 61 6e 64 62 6f 78 2e 43 68 65 63 6b 53 61 6e 64 62 6f 78 } //1 shellcodeloading/checkSandbox.CheckSandbox
		$a_81_11 = {63 72 79 70 74 6f 2f 63 69 70 68 65 72 2e 4e 65 77 43 42 43 44 65 63 72 79 70 74 65 72 } //1 crypto/cipher.NewCBCDecrypter
		$a_81_12 = {63 72 79 70 74 6f 2f 63 69 70 68 65 72 2e 78 6f 72 42 79 74 65 73 53 53 45 32 } //1 crypto/cipher.xorBytesSSE2
		$a_81_13 = {63 72 79 70 74 6f 2f 61 65 73 2e 64 65 63 72 79 70 74 42 6c 6f 63 6b 47 6f } //1 crypto/aes.decryptBlockGo
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1) >=14
 
}