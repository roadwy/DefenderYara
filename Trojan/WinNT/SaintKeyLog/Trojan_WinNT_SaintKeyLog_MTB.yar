
rule Trojan_WinNT_SaintKeyLog_MTB{
	meta:
		description = "Trojan:WinNT/SaintKeyLog!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {73 61 69 6e 74 2f 73 63 72 65 65 6e 73 68 6f 74 2f 50 4b } //01 00 
		$a_81_1 = {73 61 69 6e 74 2f 77 65 62 63 61 6d 2f 50 4b } //01 00 
		$a_81_2 = {73 61 69 6e 74 2f 6b 65 79 6c 6f 67 67 65 72 2f 50 4b } //01 00 
		$a_81_3 = {73 61 69 6e 74 2f 65 6d 61 69 6c 2f 53 65 6e 64 45 6d 61 69 6c } //00 00 
	condition:
		any of ($a_*)
 
}