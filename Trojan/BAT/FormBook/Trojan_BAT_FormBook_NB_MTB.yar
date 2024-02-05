
rule Trojan_BAT_FormBook_NB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 55 a2 cb 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 68 00 00 00 12 00 00 00 3d 00 00 00 8b 01 00 00 4f 00 00 00 af 00 00 00 02 01 00 00 01 00 00 00 22 00 00 00 0a 00 00 00 2e 00 00 00 51 } //01 00 
		$a_01_1 = {2d 32 65 33 31 63 62 31 65 34 62 36 62 } //00 00 
	condition:
		any of ($a_*)
 
}