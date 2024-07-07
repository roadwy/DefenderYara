
rule Trojan_BAT_Nanocore_GPA_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {05 0e 08 02 8e 69 6f 90 01 01 00 00 0a 0a 06 0b 2b 00 90 00 } //5
		$a_01_1 = {77 00 6d 00 57 00 4c 00 57 00 59 00 76 00 74 00 55 00 61 00 71 00 66 00 57 00 69 00 6c 00 } //5 wmWLWYvtUaqfWil
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}