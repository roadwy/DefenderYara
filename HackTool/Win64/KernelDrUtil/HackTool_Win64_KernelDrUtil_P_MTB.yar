
rule HackTool_Win64_KernelDrUtil_P_MTB{
	meta:
		description = "HackTool:Win64/KernelDrUtil.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0d 00 00 "
		
	strings :
		$a_01_0 = {5b 21 5d 20 43 61 6e 6e 6f 74 20 71 75 65 72 79 20 76 69 63 74 69 6d 20 64 72 69 76 65 72 20 69 6e 66 6f 72 6d 61 74 69 6f 6e } //1 [!] Cannot query victim driver information
		$a_01_1 = {5b 21 5d 20 43 61 6e 6e 6f 74 20 71 75 65 72 79 20 76 69 63 74 69 6d 20 64 72 69 76 65 72 20 6c 61 79 6f 75 74 } //1 [!] Cannot query victim driver layout
		$a_01_2 = {5b 21 5d 20 43 6f 75 6c 64 20 6e 6f 74 20 65 78 74 72 61 63 74 20 76 69 63 74 69 6d 20 64 72 69 76 65 72 2c 20 61 62 6f 72 74 } //1 [!] Could not extract victim driver, abort
		$a_01_3 = {5b 21 5d 20 45 72 72 6f 72 20 70 72 65 6c 6f 61 64 69 6e 67 20 76 69 63 74 69 6d 20 64 72 69 76 65 72 2c 20 61 62 6f 72 74 } //1 [!] Error preloading victim driver, abort
		$a_01_4 = {5b 21 5d 20 45 72 72 6f 72 20 77 72 69 74 69 6e 67 20 73 68 65 6c 6c 63 6f 64 65 20 74 6f 20 74 68 65 20 74 61 72 67 65 74 20 64 72 69 76 65 72 2c 20 61 62 6f 72 74 } //1 [!] Error writing shellcode to the target driver, abort
		$a_01_5 = {5b 21 5d 20 56 69 63 74 69 6d 20 64 72 69 76 65 72 20 61 6c 72 65 61 64 79 20 6c 6f 61 64 65 64 2c 20 66 6f 72 63 65 20 72 65 6c 6f 61 64 } //1 [!] Victim driver already loaded, force reload
		$a_01_6 = {5b 2b 5d 20 45 78 65 63 75 74 69 6e 67 20 73 68 65 6c 6c 63 6f 64 65 } //1 [+] Executing shellcode
		$a_01_7 = {5b 2b 5d 20 45 78 74 72 61 63 74 69 6e 67 20 76 69 63 74 69 6d 20 64 72 69 76 65 72 20 22 25 77 73 22 20 61 73 20 22 25 77 73 22 } //1 [+] Extracting victim driver "%ws" as "%ws"
		$a_01_8 = {5b 2b 5d 20 50 72 65 76 69 6f 75 73 20 69 6e 73 74 61 6e 63 65 20 6f 66 20 76 69 63 74 69 6d 20 64 72 69 76 65 72 20 75 6e 6c 6f 61 64 65 64 } //1 [+] Previous instance of victim driver unloaded
		$a_01_9 = {5b 2b 5d 20 50 72 6f 63 65 73 73 69 6e 67 20 76 69 63 74 69 6d 20 22 25 77 73 22 20 64 72 69 76 65 72 } //1 [+] Processing victim "%ws" driver
		$a_01_10 = {5b 2b 5d 20 51 75 65 72 79 20 76 69 63 74 69 6d 20 6c 6f 61 64 65 64 20 64 72 69 76 65 72 20 6c 61 79 6f 75 74 } //1 [+] Query victim loaded driver layout
		$a_01_11 = {5b 2b 5d 20 53 75 63 63 65 73 73 66 75 6c 6c 79 20 6c 6f 61 64 65 64 20 76 69 63 74 69 6d 20 64 72 69 76 65 72 } //1 [+] Successfully loaded victim driver
		$a_01_12 = {5c 48 61 6d 61 6b 61 7a 65 5c 6f 75 74 70 75 74 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 6b 64 75 2e 70 64 62 } //10 \Hamakaze\output\x64\Release\kdu.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*10) >=11
 
}