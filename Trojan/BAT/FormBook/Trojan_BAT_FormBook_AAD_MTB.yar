
rule Trojan_BAT_FormBook_AAD_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 35 00 41 00 39 00 7e 00 30 00 33 00 7e 00 7e 00 30 00 34 00 7e 00 7e 00 46 00 46 00 46 00 46 00 7e 00 30 00 42 00 38 00 7e 00 7e 00 7e 00 7e 00 30 00 30 00 34 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 30 00 30 00 38 00 7e 00 7e 00 30 00 30 00 45 00 31 00 46 00 42 00 41 00 30 00 45 00 30 00 } //1 4D5A9~03~~04~~FFFF~0B8~~~~004~~~~~~~~~~~~~~~~~~~~~~~008~~00E1FBA0E0
	condition:
		((#a_01_0  & 1)*1) >=1
 
}