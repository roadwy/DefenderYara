
rule Ransom_MSIL_Sullivan_B{
	meta:
		description = "Ransom:MSIL/Sullivan.B,SIGNATURE_TYPE_PEHSTR_EXT,6f 00 6f 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 00 6f 00 6c 00 64 00 20 00 79 00 6f 00 75 00 72 ?? 20 00 68 00 6f 00 72 00 73 00 65 00 73 00 3a 00 } //100
		$a_03_1 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6e 00 67 ?? 20 00 74 00 6f 00 6f 00 6b 00 3a 00 } //10
		$a_03_2 = {43 00 72 00 65 00 61 00 74 00 65 00 41 00 65 00 73 00 46 00 69 ?? 6c 00 65 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00 21 00 } //1
		$a_03_3 = {43 00 72 00 65 00 61 00 74 00 65 00 41 00 65 00 73 00 46 00 69 00 6c ?? 65 00 20 00 2d 00 20 00 46 00 61 00 69 00 6c 00 75 00 72 00 65 00 } //1
	condition:
		((#a_03_0  & 1)*100+(#a_03_1  & 1)*10+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=111
 
}