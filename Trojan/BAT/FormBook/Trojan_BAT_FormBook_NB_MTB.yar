
rule Trojan_BAT_FormBook_NB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 02 08 18 5a 18 ?? ?? 00 00 0a 1f 10 28 7f 00 ?? ?? 9c 00 08 17 58 0c 08 06 fe 04 0d 09 2d de } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_FormBook_NB_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 55 a2 cb 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 68 00 00 00 12 00 00 00 3d 00 00 00 8b 01 00 00 4f 00 00 00 af 00 00 00 02 01 00 00 01 00 00 00 22 00 00 00 0a 00 00 00 2e 00 00 00 51 } //1
		$a_01_1 = {2d 32 65 33 31 63 62 31 65 34 62 36 62 } //1 -2e31cb1e4b6b
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}