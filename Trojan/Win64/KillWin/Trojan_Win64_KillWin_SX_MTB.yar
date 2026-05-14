
rule Trojan_Win64_KillWin_SX_MTB{
	meta:
		description = "Trojan:Win64/KillWin.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 "
		
	strings :
		$a_01_0 = {5b 6d 61 69 6e 5d 20 53 74 65 70 20 31 3a 20 47 61 74 68 65 72 69 6e 67 20 65 6e 76 69 72 6f 6e 6d 65 6e 74 20 69 6e 66 6f } //2 [main] Step 1: Gathering environment info
		$a_01_1 = {5b 6d 61 69 6e 5d 20 53 74 65 70 20 32 3a 20 43 68 65 63 6b 69 6e 67 20 65 6e 76 69 72 6f 6e 6d 65 6e 74 20 63 6f 6e 64 69 74 69 6f 6e } //2 [main] Step 2: Checking environment condition
		$a_01_2 = {5b 6d 61 69 6e 5d 20 53 74 65 70 20 33 3a 20 55 73 65 72 20 65 6e 76 69 72 6f 6e 6d 65 6e 74 20 64 65 74 65 63 74 65 64 2e 20 45 78 65 63 75 74 69 6e 67 20 70 61 79 6c 6f 61 64 } //2 [main] Step 3: User environment detected. Executing payload
		$a_01_3 = {5b 6d 61 69 6e 5d 20 50 61 79 6c 6f 61 64 20 65 78 65 63 75 74 65 64 2e 20 45 78 69 74 69 6e 67 20 70 72 6f 67 72 61 6d 2e } //2 [main] Payload executed. Exiting program.
		$a_01_4 = {5b 6d 61 69 6e 5d 20 53 74 65 70 20 33 3a 20 53 61 6e 64 62 6f 78 20 65 6e 76 69 72 6f 6e 6d 65 6e 74 20 64 65 74 65 63 74 65 64 2e 20 45 78 69 74 69 6e 67 20 70 72 6f 67 72 61 6d 2e } //2 [main] Step 3: Sandbox environment detected. Exiting program.
		$a_01_5 = {52 65 67 69 73 74 72 79 20 6c 6f 67 67 69 6e 67 20 69 73 20 44 49 53 41 42 4c 45 44 20 28 42 45 4e 49 47 4e 5f 44 49 53 41 42 4c 45 5f 52 45 47 49 53 54 52 59 3d 31 29 } //1 Registry logging is DISABLED (BENIGN_DISABLE_REGISTRY=1)
		$a_01_6 = {54 41 53 4b 52 4f 55 54 49 4e 45 5f 44 49 53 41 42 4c 45 5f 52 45 47 49 53 54 52 59 } //1 TASKROUTINE_DISABLE_REGISTRY
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=12
 
}