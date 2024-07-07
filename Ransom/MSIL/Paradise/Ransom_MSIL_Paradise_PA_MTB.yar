
rule Ransom_MSIL_Paradise_PA_MTB{
	meta:
		description = "Ransom:MSIL/Paradise.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2c } //1 Your files have been encrypted,
		$a_01_1 = {23 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 20 00 4d 00 59 00 20 00 46 00 49 00 4c 00 45 00 53 00 23 00 } //1 #DECRYPT MY FILES#
		$a_01_2 = {5c 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 49 00 6e 00 66 00 6f 00 } //1 \DecryptionInfo
		$a_01_3 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}