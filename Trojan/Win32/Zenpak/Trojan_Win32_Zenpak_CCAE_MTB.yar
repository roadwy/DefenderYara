
rule Trojan_Win32_Zenpak_CCAE_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CCAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4b 75 75 73 6c 69 76 69 6e 67 6d } //1 Kuuslivingm
		$a_01_1 = {53 61 6a 33 56 79 68 61 64 75 70 6f 6e 59 56 } //1 Saj3VyhaduponYV
		$a_01_2 = {42 43 55 6e 74 6f 49 54 68 61 74 4e } //1 BCUntoIThatN
		$a_01_3 = {63 61 6e 2e 74 54 68 65 6d 53 77 } //1 can.tThemSw
		$a_01_4 = {62 72 6f 75 67 68 74 67 6f 6f 64 37 36 66 6f 72 35 } //1 broughtgood76for5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}