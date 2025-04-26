
rule Trojan_BAT_Remcos_LFGH_MTB{
	meta:
		description = "Trojan:BAT/Remcos.LFGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {67 65 74 5f 49 6e 76 61 6c 69 64 4f 70 65 72 61 74 69 6f 6e 5f 48 43 43 6f 75 6e 74 4f 76 65 72 66 6c 6f 77 } //1 get_InvalidOperation_HCCountOverflow
		$a_81_1 = {57 72 69 74 65 42 79 74 65 } //1 WriteByte
		$a_81_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_81_3 = {55 43 4f 4d 49 45 78 70 61 6e 64 6f } //1 UCOMIExpando
		$a_01_4 = {ed 94 ad ed 93 b7 ed 94 8f ed 93 b9 ed 93 b8 ed } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}