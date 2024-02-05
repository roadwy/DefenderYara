
rule Trojan_BAT_NetWired_ACE_MTB{
	meta:
		description = "Trojan:BAT/NetWired.ACE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {47 00 61 00 6c 00 6c 00 69 00 75 00 6d 00 53 00 50 00 49 00 43 00 45 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_80_1 = {41 57 57 64 56 46 54 6e 4a 51 4a 7a 6a 43 6d 48 7a 4a 67 4a 73 58 6c 69 70 44 68 41 2e 72 65 73 6f 75 72 63 65 73 } //AWWdVFTnJQJzjCmHzJgJsXlipDhA.resources  00 00 
	condition:
		any of ($a_*)
 
}