
rule Trojan_Win32_ProtectorEnigma_RF_MTB{
	meta:
		description = "Trojan:Win32/ProtectorEnigma.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 67 43 6c 6f 73 65 4b 65 79 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00 
		$a_00_2 = {34 00 34 00 20 00 43 00 41 00 4c 00 49 00 42 00 45 00 52 00 } //01 00 
		$a_00_3 = {49 00 6e 00 73 00 69 00 64 00 69 00 6f 00 75 00 73 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_4 = {46 75 63 6b 54 68 65 53 79 73 74 65 6d 20 43 6f 70 79 72 69 67 68 74 } //00 00 
	condition:
		any of ($a_*)
 
}