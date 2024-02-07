
rule Backdoor_Win64_TurtleLoader_UIN_dha{
	meta:
		description = "Backdoor:Win64/TurtleLoader.UIN!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {40 5b 2a 5d 20 43 61 6c 6c 69 6e 67 20 74 68 65 20 43 61 6c 6c 62 61 63 6b 20 46 75 6e 63 74 69 6f 6e 20 2e 2e 2e } //01 00  @[*] Calling the Callback Function ...
		$a_01_1 = {40 5b 2b 5d 20 53 68 65 6c 6c 63 6f 64 65 20 69 73 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 70 6c 61 63 65 64 20 62 65 74 77 65 65 6e 20 30 78 } //01 00  @[+] Shellcode is successfully placed between 0x
		$a_01_2 = {40 5b 2d 5d 20 49 6e 76 61 6c 69 64 20 55 55 49 44 20 53 74 72 69 6e 67 20 44 65 74 65 63 74 65 64 } //00 00  @[-] Invalid UUID String Detected
	condition:
		any of ($a_*)
 
}