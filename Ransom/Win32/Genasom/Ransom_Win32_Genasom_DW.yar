
rule Ransom_Win32_Genasom_DW{
	meta:
		description = "Ransom:Win32/Genasom.DW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 3e 3c 3f 78 6d 75 0c 80 7e 04 6c 75 06 80 7e 05 20 74 4d } //01 00 
		$a_01_1 = {4e 6f 77 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 69 73 20 62 6c 6f 63 6b 65 64 20 62 79 20 6e 65 77 6c 79 20 69 6e 73 74 61 6c 6c 65 64 20 73 6f 66 74 77 61 72 65 } //00 00 
	condition:
		any of ($a_*)
 
}