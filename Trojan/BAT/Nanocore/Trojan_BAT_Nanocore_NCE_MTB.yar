
rule Trojan_BAT_Nanocore_NCE_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.NCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {6f 57 00 00 0a 07 1f 10 8d 90 01 01 00 00 01 25 d0 90 01 01 00 00 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 06 07 6f 90 01 01 00 00 0a 17 73 90 01 01 00 00 0a 0c 08 02 16 02 8e 69 6f 90 01 01 00 00 0a 90 00 } //5
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_2 = {71 74 6a 69 5a 53 53 69 57 6c 47 41 66 33 53 61 76 42 2e 46 4a 72 35 34 4b 38 34 67 36 64 72 71 45 33 6a 30 75 } //1 qtjiZSSiWlGAf3SavB.FJr54K84g6drqE3j0u
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}