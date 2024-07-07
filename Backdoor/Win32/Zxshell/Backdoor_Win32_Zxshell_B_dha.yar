
rule Backdoor_Win32_Zxshell_B_dha{
	meta:
		description = "Backdoor:Win32/Zxshell.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5a 58 4e 43 20 5b 2d 6c 20 2d 66 20 2d 65 20 3c 63 6d 64 3e 5d 20 5b 2d 68 20 3c 49 50 3e 5d 20 5b 2d 70 20 3c 50 6f 72 74 3e 5d 20 5b 20 71 75 69 74 6e 63 20 5d } //1 ZXNC [-l -f -e <cmd>] [-h <IP>] [-p <Port>] [ quitnc ]
		$a_01_1 = {5a 58 4e 43 20 2d 65 20 63 6d 64 2e 65 78 65 20 78 2e 78 2e 78 2e 78 20 39 39 20 28 73 65 6e 64 20 61 20 63 6d 64 73 68 65 6c 6c 29 0d 0a } //1
		$a_01_2 = {53 68 61 72 65 53 68 65 6c 6c 20 49 50 20 50 6f 72 74 20 2d 6e 63 0d 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}