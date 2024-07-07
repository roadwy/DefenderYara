
rule Trojan_BAT_FormBook_NXP_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 82 08 00 70 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 16 07 16 1e 28 90 01 01 00 00 0a 25 07 6f 90 01 01 00 00 0a 25 18 90 00 } //1
		$a_81_1 = {73 6b 34 31 55 61 32 41 46 75 35 50 41 4e 4d 4b 69 74 2e 61 62 69 4a 50 6d 66 42 66 54 4c 36 69 4c 66 6d 61 57 } //1 sk41Ua2AFu5PANMKit.abiJPmfBfTL6iLfmaW
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}