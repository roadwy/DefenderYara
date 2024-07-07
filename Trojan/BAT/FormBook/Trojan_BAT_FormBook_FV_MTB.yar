
rule Trojan_BAT_FormBook_FV_MTB{
	meta:
		description = "Trojan:BAT/FormBook.FV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {0b 09 16 73 90 01 04 73 90 01 04 13 04 11 04 07 6f 90 01 04 dd 90 01 04 11 04 6f 90 01 04 dc 07 6f 90 01 04 13 05 dd 90 00 } //10
		$a_81_1 = {43 6c 61 73 73 4c 69 62 72 61 72 79 31 } //1 ClassLibrary1
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}