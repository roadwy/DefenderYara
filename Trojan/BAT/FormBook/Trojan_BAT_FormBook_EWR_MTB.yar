
rule Trojan_BAT_FormBook_EWR_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EWR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 00 74 00 72 00 00 09 69 00 6e 00 67 00 31 } //1
		$a_01_1 = {86 06 20 00 86 06 20 00 86 06 20 00 86 06 20 00 86 06 } //1
		$a_01_2 = {24 33 63 36 66 38 32 39 61 2d 34 34 38 34 2d 34 62 39 65 2d 62 66 38 35 2d 61 30 39 66 64 39 39 61 32 30 39 66 } //1 $3c6f829a-4484-4b9e-bf85-a09fd99a209f
		$a_01_3 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}