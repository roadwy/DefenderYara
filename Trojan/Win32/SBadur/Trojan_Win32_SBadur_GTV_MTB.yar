
rule Trojan_Win32_SBadur_GTV_MTB{
	meta:
		description = "Trojan:Win32/SBadur.GTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {64 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 42 61 74 53 63 72 69 70 74 } //downloadAndExecuteBatScript  1
		$a_01_1 = {65 73 74 61 62 6c 69 73 68 52 65 76 65 72 73 65 53 68 65 6c 6c 5f 6c 6f 67 2e 74 78 74 } //1 establishReverseShell_log.txt
		$a_01_2 = {63 6f 6d 6d 75 6e 69 63 61 74 65 57 69 74 68 43 32 5f 6c 6f 67 2e 74 78 74 } //1 communicateWithC2_log.txt
		$a_01_3 = {64 6c 6a 6d 70 32 70 2e 63 6f 6d } //1 dljmp2p.com
		$a_01_4 = {5c 74 65 72 6d 69 6e 61 74 65 53 65 63 75 72 69 74 79 50 72 6f 64 75 63 74 73 5f 6c 6f 67 2e 74 78 74 } //1 \terminateSecurityProducts_log.txt
		$a_80_5 = {5c 64 75 6d 70 43 72 65 64 65 6e 74 69 61 6c 73 5f 6c 6f 67 2e 74 78 74 } //\dumpCredentials_log.txt  1
		$a_80_6 = {74 65 72 6d 69 6e 61 74 65 42 61 63 6b 64 6f 6f 72 50 72 6f 63 65 73 73 5f 6c 6f 67 2e 74 78 74 } //terminateBackdoorProcess_log.txt  1
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}