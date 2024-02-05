
rule Trojan_UEFI_VectorEDK_RKL{
	meta:
		description = "Trojan:UEFI/VectorEDK.RKL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {ec 9a ea ea c1 c9 e2 46 9d 52 43 2a d2 5a 9b 0b } //01 00 
		$a_00_1 = {b3 8f e8 7c d7 4b 79 46 87 a8 a8 d8 de e5 0d 2b } //01 00 
		$a_02_2 = {45 33 c9 4c 8d 05 90 01 04 ba 10 00 00 00 b9 00 02 00 00 48 8b 05 90 01 04 ff 90 01 01 70 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}