
rule Trojan_Win64_BazarLoader_MCK_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.MCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {68 6f 6d 65 2f 6b 61 6c 69 2f 54 6f 6f 6c 73 2f 70 61 79 6c 6f 61 64 73 2f 4e 69 6d 48 6f 6c 6c 6f 77 2f 69 6e 6a 65 63 74 6f 72 2e 6e 69 6d } //1 home/kali/Tools/payloads/NimHollow/injector.nim
		$a_81_1 = {68 6f 6c 6c 6f 77 53 68 65 6c 6c 63 6f 64 65 } //1 hollowShellcode
		$a_81_2 = {69 6e 6a 65 63 74 6f 72 } //1 injector
		$a_81_3 = {40 5b 2a 5d 20 41 70 70 6c 79 69 6e 67 20 70 61 74 63 68 } //1 @[*] Applying patch
		$a_81_4 = {40 5b 58 5d 20 46 61 69 6c 65 64 20 74 6f 20 67 65 74 20 74 68 65 20 61 64 64 72 65 73 73 20 6f 66 20 27 45 74 77 45 76 65 6e 74 57 72 69 74 65 27 } //1 @[X] Failed to get the address of 'EtwEventWrite'
		$a_81_5 = {40 5b 2b 5d 20 45 54 57 20 50 61 74 63 68 65 64 } //1 @[+] ETW Patched
		$a_81_6 = {40 5b 2d 5d 20 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 20 64 69 64 20 6e 6f 74 20 70 61 73 73 20 74 68 65 20 63 68 65 63 6b 2c 20 65 78 69 74 69 6e 67 } //1 @[-] VirtualAllocExNuma did not pass the check, exiting
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}