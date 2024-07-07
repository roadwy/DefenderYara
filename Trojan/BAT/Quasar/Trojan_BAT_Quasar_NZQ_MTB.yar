
rule Trojan_BAT_Quasar_NZQ_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 15 00 00 0a 0b 06 16 73 16 00 00 0a 73 17 00 00 0a 0c 08 07 6f 18 00 00 0a 07 6f 19 00 00 0a 0d de 1e } //1
		$a_01_1 = {57 15 a2 09 09 01 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 26 00 00 00 06 00 00 00 04 00 00 00 10 00 00 00 02 00 00 00 27 00 00 00 16 00 00 00 03 00 00 00 02 00 00 00 04 } //1
		$a_01_2 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 WindowsFormsApp1.Properties.Resources.resource
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}