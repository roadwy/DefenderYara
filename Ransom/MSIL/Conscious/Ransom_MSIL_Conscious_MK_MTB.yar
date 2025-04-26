
rule Ransom_MSIL_Conscious_MK_MTB{
	meta:
		description = "Ransom:MSIL/Conscious.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 72 6f 6f 74 5c 63 69 6d 76 32 } //1 \root\cimv2
		$a_81_1 = {43 6f 6e 73 63 69 6f 75 73 6e 65 73 73 20 52 61 6e 73 6f 6d 77 61 72 65 20 54 65 78 74 20 4d 65 73 73 61 67 65 2e 74 78 74 } //1 Consciousness Ransomware Text Message.txt
		$a_81_2 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 Your files has been encrypted successfully
		$a_81_3 = {48 61 63 6b 69 6e 67 20 61 63 74 69 76 69 74 69 65 73 20 68 61 64 20 62 65 65 6e 20 72 75 6e 20 74 68 72 6f 75 67 68 20 6f 75 74 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 2f 4c 61 70 74 6f 70 } //1 Hacking activities had been run through out your computer/Laptop
		$a_81_4 = {74 72 61 6e 73 66 65 72 20 24 34 30 30 2e 30 30 20 74 6f 20 75 73 20 77 69 74 68 20 62 69 74 63 6f 69 6e } //1 transfer $400.00 to us with bitcoin
		$a_81_5 = {2e 43 6f 6e 73 63 69 6f 75 73 6e 65 73 73 } //1 .Consciousness
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}