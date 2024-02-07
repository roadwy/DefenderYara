
rule Trojan_Win32_Vebzenpak_RF_MTB{
	meta:
		description = "Trojan:Win32/Vebzenpak.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_81_0 = {46 75 6c 64 62 6c 6f 64 73 6f 70 64 72 74 74 65 72 } //02 00  Fuldblodsopdrtter
		$a_81_1 = {4e 76 6e 46 69 71 44 36 41 50 48 6a 31 41 7a 41 4c 57 30 5a 47 37 58 5a 70 30 67 6d 47 66 43 6b 55 71 4d 58 31 38 35 } //01 00  NvnFiqD6APHj1AzALW0ZG7XZp0gmGfCkUqMX185
		$a_81_2 = {64 65 66 69 6e 69 74 69 6f 6e 73 6a 6f 6e 67 6c 65 72 69 } //00 00  definitionsjongleri
	condition:
		any of ($a_*)
 
}