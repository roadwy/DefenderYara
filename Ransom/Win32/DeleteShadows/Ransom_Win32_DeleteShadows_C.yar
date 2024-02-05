
rule Ransom_Win32_DeleteShadows_C{
	meta:
		description = "Ransom:Win32/DeleteShadows.C,SIGNATURE_TYPE_CMDHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {73 00 79 00 73 00 6e 00 61 00 74 00 69 00 76 00 65 00 5c 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_00_1 = {73 00 68 00 61 00 64 00 6f 00 77 00 73 00 } //01 00 
		$a_00_2 = {64 00 65 00 6c 00 65 00 74 00 65 00 } //01 00 
		$a_00_3 = {2f 00 61 00 6c 00 6c 00 } //01 00 
		$a_00_4 = {2f 00 71 00 75 00 69 00 65 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}