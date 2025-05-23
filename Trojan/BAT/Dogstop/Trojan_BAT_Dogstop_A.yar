
rule Trojan_BAT_Dogstop_A{
	meta:
		description = "Trojan:BAT/Dogstop.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {c2 a9 20 48 61 63 6b 69 6e 67 20 26 20 43 6f } //1
		$a_01_1 = {4b 00 39 00 52 00 65 00 6d 00 6f 00 76 00 65 00 72 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 K9Remover.Resources
		$a_01_2 = {4e 00 6f 00 77 00 20 00 61 00 74 00 74 00 65 00 6d 00 70 00 74 00 69 00 6e 00 67 00 20 00 74 00 6f 00 20 00 72 00 65 00 6d 00 6f 00 76 00 65 00 20 00 4b 00 39 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00 } //1 Now attempting to remove K9 Driver
		$a_01_3 = {4d 79 41 70 70 6c 69 63 61 74 69 6f 6e 00 4b 39 52 65 6d 6f 76 65 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}