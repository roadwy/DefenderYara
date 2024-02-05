
rule Trojan_Win32_Iceid_PC_MTB{
	meta:
		description = "Trojan:Win32/Iceid.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 4e 49 5f 4f 6e 4c 6f 61 64 } //01 00 
		$a_01_1 = {69 6e 69 74 } //01 00 
		$a_01_2 = {68 61 76 61 5f 63 6f 6d 5f 73 75 6e 5f 69 6d 61 67 65 69 6f 5f 70 6c 75 67 69 6e 73 5f 6a 70 65 67 5f 4a 50 45 47 49 6d 61 67 65 52 65 61 64 65 72 5f } //01 00 
		$a_01_3 = {68 61 76 61 5f 63 6f 6d 5f 73 75 6e 5f 69 6d 61 67 65 69 6f 5f 70 6c 75 67 69 6e 73 5f 6a 70 65 67 5f 4a 50 45 47 49 6d 61 67 65 57 72 69 74 65 72 5f } //01 00 
		$a_01_4 = {6a 61 76 61 6a 70 65 67 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}