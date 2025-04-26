
rule Trojan_BAT_CryptInject_UK_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.UK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {53 68 6f 72 74 50 66 61 66 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 66 64 64 64 72 6f 63 65 73 73 20 43 6f 6d 70 6c 65 74 65 64 } //1 ShortPfafddddddddddddddddfdddrocess Completed
		$a_81_1 = {53 68 6f 72 74 50 64 64 64 64 64 64 66 64 64 64 64 64 64 64 64 64 64 66 64 64 64 72 6f 63 65 73 73 20 43 6f 6d 70 6c 65 74 65 64 } //1 ShortPddddddfddddddddddfdddrocess Completed
		$a_81_2 = {53 68 6f 72 74 50 64 64 64 64 64 64 64 64 64 64 66 6d 70 6c 65 74 65 64 } //1 ShortPddddddddddfmpleted
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}