
rule Ransom_Win32_Genasom_D{
	meta:
		description = "Ransom:Win32/Genasom.D,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3f 75 63 6f 64 65 3d 00 43 6f 6f 6b 69 65 00 00 4d 65 64 69 61 56 69 65 77 00 00 00 52 65 67 69 73 74 54 00 52 65 67 69 73 74 44 00 52 65 67 69 73 74 49 44 } //01 00 
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4b 4a 5c 53 68 61 72 65 5c 44 61 74 65 49 6e 66 6f 5c 57 61 72 65 6b 69 5c } //00 00 
	condition:
		any of ($a_*)
 
}