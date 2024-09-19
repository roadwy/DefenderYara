
rule Trojan_BAT_Taskun_SO_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {5f 95 d2 13 10 11 0e 11 10 61 13 11 11 07 11 08 d4 11 11 } //2
		$a_01_1 = {4c 69 62 72 61 72 79 2e 4c 69 62 72 61 72 79 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //2 Library.LibraryForm.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}