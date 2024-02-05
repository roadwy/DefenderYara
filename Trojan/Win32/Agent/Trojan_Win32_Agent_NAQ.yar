
rule Trojan_Win32_Agent_NAQ{
	meta:
		description = "Trojan:Win32/Agent.NAQ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {43 63 63 68 6f 73 74 44 6f 63 90 05 10 02 01 00 43 63 63 68 6f 73 74 56 69 65 77 90 05 10 02 01 00 63 63 68 6f 73 74 2e 65 78 65 90 05 10 02 01 00 70 68 70 2e 90 02 10 2f 68 63 74 61 77 65 74 6f 6d 65 72 2f 74 65 6e 2e 90 02 20 2f 2f 3a 70 74 74 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}