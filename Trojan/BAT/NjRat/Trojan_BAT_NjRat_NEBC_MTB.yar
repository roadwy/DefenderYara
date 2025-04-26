
rule Trojan_BAT_NjRat_NEBC_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_03_0 = {0b 06 07 16 1a 28 ?? 00 00 06 26 07 16 28 ?? 00 00 06 0c 06 16 73 ?? 00 00 0a 0d 08 8d 26 00 00 01 13 04 } //5
		$a_03_1 = {46 00 00 00 26 20 02 00 00 00 38 1d 00 00 00 09 11 04 16 08 28 ?? 00 00 06 26 } //5
		$a_01_2 = {44 65 63 6f 6d 70 72 65 73 73 } //2 Decompress
		$a_01_3 = {52 50 46 3a 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 } //2 RPF:SmartAssembly
		$a_01_4 = {53 79 73 74 65 6d 2e 57 69 6e 64 6f 77 73 2e 46 6f 72 6d 73 } //2 System.Windows.Forms
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=16
 
}