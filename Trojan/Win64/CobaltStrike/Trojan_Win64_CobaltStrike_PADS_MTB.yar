
rule Trojan_Win64_CobaltStrike_PADS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PADS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 65 67 69 6e 6e 69 6e 67 20 73 61 6e 64 62 6f 78 20 65 76 61 73 69 6f 6e 20 72 6f 75 74 69 6e 65 } //01 00  Beginning sandbox evasion routine
		$a_01_1 = {54 68 69 73 20 69 73 20 70 72 6f 62 61 62 6c 79 20 61 20 73 61 6e 64 62 6f 78 2c 20 6f 72 20 73 6f 6d 65 6f 6e 65 20 61 74 74 61 63 68 65 64 20 61 20 64 65 62 75 67 67 65 72 20 61 6e 64 20 73 74 65 70 70 65 64 20 6f 76 65 72 20 74 68 65 20 6c 6f 6f 70 } //01 00  This is probably a sandbox, or someone attached a debugger and stepped over the loop
		$a_01_2 = {53 68 65 6c 6c 63 6f 64 65 20 64 65 63 72 79 70 74 69 6f 6e 20 63 6f 6d 70 6c 65 74 65 2e } //01 00  Shellcode decryption complete.
		$a_01_3 = {54 61 73 6b 65 64 20 74 6f 20 77 72 69 74 65 20 73 68 65 6c 6c 63 6f 64 65 20 74 6f 20 61 6c 6c 6f 63 61 74 65 64 20 6d 65 6d 6f 72 79 20 69 6e 20 74 68 65 20 74 61 72 67 65 74 20 70 72 6f 63 65 73 73 } //00 00  Tasked to write shellcode to allocated memory in the target process
	condition:
		any of ($a_*)
 
}