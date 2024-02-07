
rule Trojan_BAT_Remcos_GHAZ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.GHAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,37 00 37 00 06 00 00 0a 00 "
		
	strings :
		$a_81_0 = {47 65 74 4d 65 74 68 6f 64 } //0a 00  GetMethod
		$a_81_1 = {52 65 70 6c 61 63 65 } //0a 00  Replace
		$a_81_2 = {49 6e 76 6f 6b 65 } //0a 00  Invoke
		$a_81_3 = {52 65 76 65 72 73 65 } //0a 00  Reverse
		$a_81_4 = {54 6f 41 72 72 61 79 } //05 00  ToArray
		$a_80_5 = {68 74 74 70 3a 2f 2f 74 72 69 65 74 6c 6f 6e 67 76 69 6e 68 76 69 65 6e 2e 69 6e 66 6f 2f 2f 2e 74 6d 62 2f } //http://trietlongvinhvien.info//.tmb/  00 00 
	condition:
		any of ($a_*)
 
}