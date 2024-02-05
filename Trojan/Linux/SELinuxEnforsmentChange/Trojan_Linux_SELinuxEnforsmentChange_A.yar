
rule Trojan_Linux_SELinuxEnforsmentChange_A{
	meta:
		description = "Trojan:Linux/SELinuxEnforsmentChange.A,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {30 00 20 00 3e 00 20 00 2f 00 73 00 79 00 73 00 2f 00 66 00 73 00 2f 00 73 00 65 00 6c 00 69 00 6e 00 75 00 78 00 2f 00 65 00 6e 00 66 00 6f 00 72 00 63 00 65 00 } //0a 00 
		$a_00_1 = {30 00 3e 00 2f 00 73 00 79 00 73 00 2f 00 66 00 73 00 2f 00 73 00 65 00 6c 00 69 00 6e 00 75 00 78 00 2f 00 65 00 6e 00 66 00 6f 00 72 00 63 00 65 00 } //0a 00 
		$a_00_2 = {73 00 65 00 74 00 65 00 6e 00 66 00 6f 00 72 00 63 00 65 00 20 00 30 00 } //00 00 
	condition:
		any of ($a_*)
 
}