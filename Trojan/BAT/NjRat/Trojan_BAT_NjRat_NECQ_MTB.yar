
rule Trojan_BAT_NjRat_NECQ_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 00 06 0b 07 6f ?? 00 00 0a 17 da 0c 16 0d 2b 20 7e ?? 03 00 04 07 09 16 6f ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 17 d6 0d 09 08 31 dc } //10
		$a_01_1 = {57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 5f 00 52 00 65 00 63 00 75 00 72 00 73 00 69 00 76 00 65 00 46 00 6f 00 72 00 6d 00 43 00 72 00 65 00 61 00 74 00 65 00 } //4 WinForms_RecursiveFormCreate
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*4) >=14
 
}