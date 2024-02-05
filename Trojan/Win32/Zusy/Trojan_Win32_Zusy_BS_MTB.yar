
rule Trojan_Win32_Zusy_BS_MTB{
	meta:
		description = "Trojan:Win32/Zusy.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 6f 67 69 6f 73 77 69 6f 67 68 73 77 6f 69 68 6a 73 72 6a 68 } //02 00 
		$a_01_1 = {4b 6f 69 6f 73 64 66 68 67 69 69 49 69 6a 73 68 67 69 73 72 6a 68 } //02 00 
		$a_01_2 = {6b 76 6a 70 73 67 6a 77 73 65 69 6f 67 6a 77 69 6f 6a 68 67 } //01 00 
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}