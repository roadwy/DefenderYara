
rule Trojan_BAT_FormBook_ABSC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 6c 69 63 61 74 69 6f 6e 36 2e 4f 70 65 6e 69 6e 67 73 63 72 65 65 6e 2e 72 65 73 6f 75 72 63 65 73 } //4 WindowsFormsApplication6.Openingscreen.resources
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 6c 69 63 61 74 69 6f 6e 36 2e 50 72 6f 70 65 72 74 69 65 73 } //1 WindowsFormsApplication6.Properties
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}