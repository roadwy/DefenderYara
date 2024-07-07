
rule Trojan_BAT_DcRat_NEAG_MTB{
	meta:
		description = "Trojan:BAT/DcRat.NEAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {00 02 11 04 09 6f 90 01 01 00 00 0a 13 05 06 12 05 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 26 00 11 04 17 58 13 04 11 04 07 fe 02 16 fe 01 13 06 11 06 2d d1 00 09 17 58 0d 90 00 } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}