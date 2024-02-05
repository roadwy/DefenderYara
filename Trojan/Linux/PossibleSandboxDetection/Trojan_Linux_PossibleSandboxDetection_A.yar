
rule Trojan_Linux_PossibleSandboxDetection_A{
	meta:
		description = "Trojan:Linux/PossibleSandboxDetection.A,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {2f 00 73 00 79 00 73 00 2f 00 63 00 6c 00 61 00 73 00 73 00 2f 00 64 00 6d 00 69 00 2f 00 69 00 64 00 2f 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 5f 00 6e 00 61 00 6d 00 65 00 } //0a 00 
		$a_00_1 = {2f 00 73 00 79 00 73 00 2f 00 63 00 6c 00 61 00 73 00 73 00 2f 00 64 00 6d 00 69 00 2f 00 69 00 64 00 2f 00 73 00 79 00 73 00 5f 00 76 00 65 00 6e 00 64 00 6f 00 72 00 } //0a 00 
		$a_00_2 = {2f 00 70 00 72 00 6f 00 63 00 2f 00 78 00 65 00 6e 00 2f 00 63 00 61 00 70 00 61 00 62 00 69 00 6c 00 69 00 74 00 69 00 65 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}