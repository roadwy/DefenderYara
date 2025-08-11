
rule Ransom_Win64_Filecoder_UDP_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.UDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {52 61 6e 73 6f 6d 77 61 72 65 20 53 69 6d 75 6c 61 74 69 6f 6e } //1 Ransomware Simulation
		$a_81_1 = {44 65 66 65 6e 73 65 45 76 61 73 69 6f 6e 2b 3c 3e 63 2b 3c 3c 44 69 73 61 62 6c 65 53 65 63 75 72 69 74 79 53 6f 66 74 77 61 72 65 3e } //1 DefenseEvasion+<>c+<<DisableSecuritySoftware>
		$a_81_2 = {3c 45 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 69 65 73 3e } //1 <EncryptDirectories>
		$a_81_3 = {3c 44 69 73 61 62 6c 65 53 65 63 75 72 69 74 79 53 6f 66 74 77 61 72 65 3e } //1 <DisableSecuritySoftware>
		$a_81_4 = {45 6e 73 75 72 65 52 75 6e 6e 69 6e 67 41 73 41 64 6d 69 6e } //1 EnsureRunningAsAdmin
		$a_81_5 = {4d 6f 64 65 72 6e 20 57 6f 6f 64 6d 65 6e 20 6f 66 20 41 6d 65 72 69 63 61 } //1 Modern Woodmen of America
		$a_81_6 = {43 6f 6d 6d 61 6e 64 20 26 20 43 6f 6e 74 72 6f 6c } //1 Command & Control
		$a_81_7 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin delete shadows /all /quiet
		$a_81_8 = {50 61 79 20 74 68 65 20 72 61 6e 73 6f 6d 20 74 6f 20 67 65 74 20 74 68 65 20 64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 2e } //1 Pay the ransom to get the decryption key.
		$a_81_9 = {64 65 74 65 63 74 20 61 6e 64 20 73 74 6f 70 20 41 56 20 26 20 45 44 52 } //1 detect and stop AV & EDR
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}