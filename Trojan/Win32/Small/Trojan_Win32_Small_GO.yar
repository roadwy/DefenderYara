
rule Trojan_Win32_Small_GO{
	meta:
		description = "Trojan:Win32/Small.GO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 5c 68 64 70 2e 65 78 65 } //01 00 
		$a_01_1 = {2e 68 65 6e 62 61 6e 67 2e 6e 65 74 } //01 00 
		$a_01_2 = {25 73 5c 68 65 6e 62 61 6e 67 74 65 6d 70 } //01 00 
		$a_01_3 = {25 73 5c 64 69 73 74 72 69 62 75 74 65 72 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}