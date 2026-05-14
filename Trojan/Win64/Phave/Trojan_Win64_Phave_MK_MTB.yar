
rule Trojan_Win64_Phave_MK_MTB{
	meta:
		description = "Trojan:Win64/Phave.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 04 00 00 "
		
	strings :
		$a_81_0 = {5b 2b 5d 20 45 6e 61 62 6c 65 20 25 6c 73 20 70 72 69 76 69 6c 65 67 65 } //15 [+] Enable %ls privilege
		$a_01_1 = {46 61 69 6c 65 64 20 74 6f 20 65 6e 61 62 6c 65 20 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 2e 20 59 6f 75 20 6d 69 67 68 74 20 6e 6f 74 20 68 61 76 65 20 73 75 66 66 69 63 69 65 6e 74 20 72 69 67 68 74 73 2e } //10 Failed to enable SeDebugPrivilege. You might not have sufficient rights.
		$a_01_2 = {46 61 69 6c 65 64 20 74 6f 20 77 72 69 74 65 20 74 6f 20 74 61 72 67 65 74 20 70 72 6f 63 65 73 73 20 6d 65 6d 6f 72 79 2e 20 45 72 72 6f 72 3a 20 25 64 } //3 Failed to write to target process memory. Error: %d
		$a_01_3 = {54 68 69 73 20 70 72 6f 67 72 61 6d 20 69 73 20 72 75 6e 6e 69 6e 67 20 66 72 6f 6d 3a 20 25 73 } //2 This program is running from: %s
	condition:
		((#a_81_0  & 1)*15+(#a_01_1  & 1)*10+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=30
 
}