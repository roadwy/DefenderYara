
rule Trojan_Win64_SlipHammer_A_dha{
	meta:
		description = "Trojan:Win64/SlipHammer.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 66 00 69 00 6c 00 6c 00 65 00 64 00 20 00 77 00 69 00 74 00 68 00 20 00 73 00 70 00 61 00 63 00 65 00 73 00 20 00 74 00 6f 00 20 00 6d 00 61 00 74 00 63 00 68 00 20 00 69 00 74 00 73 00 20 00 6f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 20 00 73 00 69 00 7a 00 65 00 2e 00 } //1 has been filled with spaces to match its original size.
		$a_01_1 = {57 00 61 00 72 00 6e 00 69 00 6e 00 67 00 3a 00 20 00 46 00 69 00 6c 00 65 00 20 00 73 00 69 00 7a 00 65 00 20 00 6d 00 69 00 73 00 6d 00 61 00 74 00 63 00 68 00 20 00 61 00 66 00 74 00 65 00 72 00 20 00 66 00 69 00 6c 00 6c 00 69 00 6e 00 67 00 21 00 20 00 45 00 78 00 70 00 65 00 63 00 74 00 65 00 64 00 } //1 Warning: File size mismatch after filling! Expected
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}