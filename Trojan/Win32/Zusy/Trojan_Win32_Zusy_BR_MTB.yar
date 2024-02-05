
rule Trojan_Win32_Zusy_BR_MTB{
	meta:
		description = "Trojan:Win32/Zusy.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {42 69 6f 73 6a 68 6f 69 73 66 6a 41 6f 69 73 6a 69 68 6a 72 65 } //02 00 
		$a_01_1 = {4b 73 6f 69 67 6a 73 41 6a 73 68 6a 72 69 6a 68 } //02 00 
		$a_01_2 = {4c 73 69 6f 72 68 6a 69 73 72 49 6a 69 6a 68 72 } //01 00 
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}