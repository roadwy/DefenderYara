
rule Trojan_Win32_Fareit_RDL_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RDL!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6f 00 72 00 65 00 47 00 4b 00 75 00 54 00 78 00 5a 00 45 00 5a 00 48 00 6c 00 33 00 35 00 } //1 oreGKuTxZEZHl35
		$a_01_1 = {44 00 6b 00 50 00 31 00 32 00 36 00 4a 00 4c 00 46 00 51 00 54 00 6e 00 4b 00 39 00 76 00 37 00 5a 00 66 00 32 00 6f 00 4d 00 36 00 31 00 } //1 DkP126JLFQTnK9v7Zf2oM61
		$a_01_2 = {44 00 34 00 7a 00 46 00 4e 00 74 00 57 00 5a 00 4b 00 67 00 31 00 49 00 55 00 55 00 56 00 4c 00 47 00 33 00 67 00 47 00 75 00 6b 00 4b 00 7a 00 32 00 69 00 65 00 65 00 31 00 4c 00 31 00 37 00 34 00 } //1 D4zFNtWZKg1IUUVLG3gGukKz2iee1L174
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}