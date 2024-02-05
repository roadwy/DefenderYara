
rule Ransom_Win32_Genasom_BO{
	meta:
		description = "Ransom:Win32/Genasom.BO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 49 43 52 4f 53 4f 46 54 20 53 59 53 54 45 4d 20 53 45 43 55 52 49 54 59 00 } //01 00 
		$a_01_1 = {6f 00 62 00 6a 00 5f 00 45 00 44 00 49 00 54 00 00 00 } //01 00 
		$a_01_2 = {27 00 6d 00 79 00 6e 00 75 00 6d 00 00 00 } //01 00 
		$a_02_3 = {66 81 7f 04 05 b0 75 73 51 0f b7 4f 0a 8b 73 4c 66 3b 4e 20 75 1b 80 bb 26 01 00 00 00 7f 4e 89 d8 b2 01 e8 90 01 02 ff ff 89 d8 e8 90 01 02 00 00 eb 3c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}