
rule Trojan_Win64_Envdropper_DA_MTB{
	meta:
		description = "Trojan:Win64/Envdropper.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_80_0 = {41 74 74 65 6d 70 74 69 6e 67 20 6c 61 74 65 72 61 6c 20 6d 6f 76 65 6d 65 6e 74 2e 2e 2e } //Attempting lateral movement...  10
		$a_80_1 = {65 6e 76 64 72 6f 70 70 65 72 } //envdropper  10
		$a_80_2 = {44 65 62 75 67 67 65 72 20 6f 72 20 6d 6f 6e 69 74 6f 72 69 6e 67 20 74 6f 6f 6c 20 64 65 74 65 63 74 65 64 21 20 53 65 6c 66 2d 64 65 73 74 72 75 63 74 69 6e 67 2e 2e 2e } //Debugger or monitoring tool detected! Self-destructing...  1
		$a_80_3 = {44 65 62 75 67 67 65 72 20 64 65 74 65 63 74 65 64 21 20 45 78 69 74 69 6e 67 2e } //Debugger detected! Exiting.  1
		$a_80_4 = {45 6e 63 72 79 70 74 69 6f 6e 20 61 6e 64 20 64 65 63 72 79 70 74 69 6f 6e 20 63 6f 6d 70 6c 65 74 65 64 2e } //Encryption and decryption completed.  1
		$a_80_5 = {4e 6f 20 76 69 72 74 75 61 6c 69 7a 61 74 69 6f 6e 20 6f 72 20 6f 62 73 65 72 76 61 74 69 6f 6e 20 64 65 74 65 63 74 65 64 2e 20 53 61 66 65 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e } //No virtualization or observation detected. Safe to continue.  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=12
 
}