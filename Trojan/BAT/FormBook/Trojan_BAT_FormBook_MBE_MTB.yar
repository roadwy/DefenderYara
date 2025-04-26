
rule Trojan_BAT_FormBook_MBE_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 50 00 23 00 65 00 73 00 2e 00 57 00 68 00 23 00 74 00 65 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 } //1          P#es.Wh#te          
		$a_01_1 = {20 00 20 00 20 00 50 00 69 00 40 00 73 00 2e 00 57 00 68 00 69 00 74 00 40 00 20 00 } //1    Pi@s.Whit@ 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}