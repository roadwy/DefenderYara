
rule Ransom_Win32_Qilin_AK{
	meta:
		description = "Ransom:Win32/Qilin.AK,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 "
		
	strings :
		$a_81_0 = {50 61 79 6c 6f 61 64 20 65 78 65 63 75 74 65 64 20 61 6e 64 20 65 6e 63 72 79 70 74 69 6f 6e 20 70 72 6f 63 65 73 73 20 73 74 61 72 74 65 64 } //10 Payload executed and encryption process started
		$a_81_1 = {5b 45 52 52 4f 52 7c 57 41 4c 4c 5d 20 45 72 72 6f 72 20 77 72 69 74 69 6e 67 20 77 61 6c 6c 70 61 70 65 72 20 74 6f 20 64 69 73 6b } //1 [ERROR|WALL] Error writing wallpaper to disk
		$a_81_2 = {48 76 48 79 70 65 72 2d 56 56 4d 77 61 72 65 56 4d 77 61 72 65 56 4d 77 61 72 65 56 42 6f 78 56 42 6f 78 56 42 6f 78 56 69 72 74 75 61 6c 42 6f 78 4b 56 4d 4b 56 4d 4b 56 4d } //1 HvHyper-VVMwareVMwareVMwareVBoxVBoxVBoxVirtualBoxKVMKVMKVM
		$a_81_3 = {5b 49 4e 46 4f 7c 4d 55 54 45 58 5d 20 4f 77 6e 65 72 73 68 69 70 20 6f 66 20 6d 75 74 65 78 20 74 61 6b 65 6e 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 [INFO|MUTEX] Ownership of mutex taken successfully
		$a_81_4 = {5b 49 4e 46 4f 7c 56 4d 5d 20 4d 61 63 68 69 6e 65 20 64 65 74 65 63 74 65 64 20 61 73 20 70 68 79 73 69 63 61 6c } //1 [INFO|VM] Machine detected as physical
		$a_81_5 = {5b 49 4e 46 4f 7c 56 4d 5d 20 4d 61 63 68 69 6e 65 20 64 65 74 65 63 74 65 64 20 61 73 20 61 20 76 69 72 74 75 61 6c 20 6d 61 63 68 69 6e 65 } //1 [INFO|VM] Machine detected as a virtual machine
		$a_81_6 = {5b 49 4e 46 4f 7c 56 4d 5d 20 43 6f 75 6c 64 20 62 65 20 66 61 6c 73 65 20 70 6f 73 69 74 69 76 65 2e 20 50 65 72 66 6f 72 6d 69 6e 67 20 6f 74 68 65 72 20 63 68 65 63 6b 73 } //1 [INFO|VM] Could be false positive. Performing other checks
		$a_81_7 = {5b 49 4e 46 4f 7c 56 4d 5d 20 4e 6f 20 67 75 65 73 74 20 56 4d 20 6b 65 79 20 64 65 74 65 63 74 65 64 2e 20 4d 61 72 6b 69 6e 67 20 61 73 20 66 61 6c 73 65 20 70 6f 73 69 74 69 76 65 } //1 [INFO|VM] No guest VM key detected. Marking as false positive
		$a_81_8 = {5b 49 4e 46 4f 7c 56 4d 5d 20 48 79 70 65 72 2d 56 20 67 75 65 73 74 20 6b 65 79 20 64 65 74 65 63 74 65 64 2e 20 54 68 69 73 20 69 73 20 61 20 56 4d } //1 [INFO|VM] Hyper-V guest key detected. This is a VM
		$a_81_9 = {5b 49 4e 46 4f 7c 56 4d 5d 20 4d 61 63 68 69 6e 65 20 64 65 74 65 63 74 65 64 20 61 73 20 56 4d 20 69 6e 73 69 64 65 20 20 68 79 70 65 72 76 69 73 6f 72 } //1 [INFO|VM] Machine detected as VM inside  hypervisor
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=11
 
}