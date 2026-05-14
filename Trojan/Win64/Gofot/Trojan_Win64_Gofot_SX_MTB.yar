
rule Trojan_Win64_Gofot_SX_MTB{
	meta:
		description = "Trojan:Win64/Gofot.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 08 00 00 "
		
	strings :
		$a_01_0 = {5b 2b 5d 20 49 6e 6a 65 63 74 69 6f 6e 20 50 72 6f 63 65 73 73 } //10 [+] Injection Process
		$a_01_1 = {5b 2b 5d 20 45 6d 75 6c 61 74 6f 72 20 44 65 74 65 63 74 65 64 } //5 [+] Emulator Detected
		$a_01_2 = {5b 2b 5d 20 55 70 64 61 74 65 64 20 43 6f 64 65 73 } //5 [+] Updated Codes
		$a_01_3 = {5b 2b 5d 20 43 68 65 63 6b 69 6e 67 20 55 70 64 61 74 65 73 } //1 [+] Checking Updates
		$a_01_4 = {5b 2d 5d 20 55 70 64 61 74 65 20 66 61 69 6c 65 64 2c 20 72 65 74 72 79 69 6e 67 } //1 [-] Update failed, retrying
		$a_01_5 = {5b 2b 5d 20 50 72 6f 63 65 73 73 20 44 65 74 65 63 74 65 64 } //1 [+] Process Detected
		$a_01_6 = {5b 2d 5d 20 4d 61 69 6e 20 6d 6f 64 75 6c 65 20 6d 69 73 73 69 6e 67 2c 20 72 65 2d 64 6f 77 6e 6c 6f 61 64 69 6e 67 } //1 [-] Main module missing, re-downloading
		$a_01_7 = {5b 2b 5d 20 53 75 63 63 65 73 73 66 75 6c 6c 79 20 4c 6f 61 64 65 64 } //1 [+] Successfully Loaded
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=25
 
}