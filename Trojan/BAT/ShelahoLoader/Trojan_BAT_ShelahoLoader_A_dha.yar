
rule Trojan_BAT_ShelahoLoader_A_dha{
	meta:
		description = "Trojan:BAT/ShelahoLoader.A!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5b 00 2b 00 5d 00 20 00 53 00 74 00 61 00 72 00 74 00 69 00 6e 00 67 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //1 [+] Starting shell process
		$a_01_1 = {5b 00 78 00 5d 00 20 00 46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 72 00 65 00 61 00 64 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 6d 00 65 00 6d 00 6f 00 72 00 79 00 21 00 } //1 [x] Failed to read process memory!
		$a_01_2 = {5b 00 78 00 5d 00 20 00 53 00 68 00 65 00 6c 00 6c 00 63 00 6f 00 64 00 65 00 20 00 62 00 75 00 66 00 66 00 65 00 72 00 20 00 69 00 73 00 20 00 74 00 6f 00 6f 00 20 00 6c 00 6f 00 6e 00 67 00 21 00 } //1 [x] Shellcode buffer is too long!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}