
rule Trojan_Win64_GaryStealer_A_MTB{
	meta:
		description = "Trojan:Win64/GaryStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 43 6f 64 65 33 33 2f 56 4d 2d 44 65 74 65 63 74 69 6f 6e } //2 ShellCode33/VM-Detection
		$a_01_1 = {67 61 72 79 2d 6d 61 63 6f 73 2d 73 74 65 61 6c 65 72 2d 6d 61 6c 77 61 72 65 2f 61 67 65 6e 74 2f 77 69 6e } //2 gary-macos-stealer-malware/agent/win
		$a_01_2 = {73 65 72 76 65 72 20 66 69 6e 69 73 68 65 64 } //2 server finished
		$a_01_3 = {65 78 74 65 6e 64 65 64 20 6d 61 73 74 65 72 20 73 65 63 72 65 74 } //2 extended master secret
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}