
rule Trojan_BAT_Remcos_SUJ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SUJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_02_0 = {00 02 6f 89 00 00 0a 18 5b 8d 76 00 00 01 0a 16 0b 2b 1a 00 06 07 02 07 18 5a 18 90 02 05 1f 10 28 8b 00 00 0a 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d dc 90 00 } //1
		$a_81_1 = {41 73 6e 61 6e 79 44 65 6e 74 61 6c 43 6c 69 6e 69 63 2e 50 72 6f 70 65 72 74 69 65 73 } //1 AsnanyDentalClinic.Properties
		$a_81_2 = {42 69 74 6d 61 70 } //1 Bitmap
		$a_81_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_4 = {53 70 6c 69 74 } //1 Split
		$a_81_5 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}