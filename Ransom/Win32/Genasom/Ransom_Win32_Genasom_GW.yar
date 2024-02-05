
rule Ransom_Win32_Genasom_GW{
	meta:
		description = "Ransom:Win32/Genasom.GW,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 06 6a 01 6a 02 ff 15 e4 20 40 00 6a 02 8b f0 58 68 90 01 04 66 89 45 f0 ff 15 90 01 04 6a 50 89 45 f4 ff 15 90 00 } //01 00 
		$a_01_1 = {2f 6e 2f 67 65 74 2e 70 68 70 3f 70 69 6e 3d } //01 00 
		$a_01_2 = {2f 6e 2f 67 65 74 2e 70 68 70 3f 6f 74 3d } //01 00 
		$a_01_3 = {57 65 20 61 72 65 20 70 72 6f 63 65 73 73 69 6e 67 20 79 6f 75 72 20 70 61 79 6d 65 6e 74 2e } //01 00 
		$a_01_4 = {53 69 6c 65 6e 63 65 5f 6c 6f 63 6b 5f 62 6f 74 } //00 00 
	condition:
		any of ($a_*)
 
}