
rule Ransom_Win32_Conti_PA_MTB{
	meta:
		description = "Ransom:Win32/Conti.PA!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 00 4f 00 4e 00 54 00 49 00 5f 00 52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 74 00 78 00 74 00 } //1 CONTI_README.txt
		$a_01_1 = {59 6f 75 72 20 73 79 73 74 65 6d 20 69 73 20 4c 4f 43 4b 45 44 2e 20 57 72 69 74 65 20 75 73 20 6f 6e 20 74 68 65 20 65 6d 61 69 6c 73 } //1 Your system is LOCKED. Write us on the emails
		$a_01_2 = {44 4f 20 4e 4f 54 20 54 52 59 20 74 6f 20 64 65 63 72 79 70 74 20 66 69 6c 65 73 20 75 73 69 6e 67 20 6f 74 68 65 72 20 73 6f 66 74 77 61 72 65 2e } //1 DO NOT TRY to decrypt files using other software.
		$a_01_3 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 @protonmail.com
		$a_01_4 = {2e 00 43 00 4f 00 4e 00 54 00 49 00 } //1 .CONTI
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}