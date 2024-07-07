
rule Trojan_BAT_Formbook_NUK_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NUK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {53 68 6f 72 74 50 66 61 66 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 64 66 64 64 64 72 6f 63 65 73 73 20 43 6f 6d 70 6c 65 74 65 64 } //1 ShortPfafddddddddddddddddfdddrocess Completed
		$a_81_1 = {53 68 6f 72 74 50 64 64 64 64 64 64 66 64 64 64 64 64 64 64 64 64 64 66 64 64 64 72 6f 63 65 73 73 20 43 6f 6d 70 6c 65 74 65 64 } //1 ShortPddddddfddddddddddfdddrocess Completed
		$a_81_2 = {53 68 6f 72 74 50 64 64 64 64 64 64 64 64 64 64 66 6d 70 6c 65 74 65 64 } //1 ShortPddddddddddfmpleted
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {64 61 73 64 20 43 6f 6d 70 6c 65 74 65 64 } //1 dasd Completed
		$a_81_5 = {66 61 66 20 43 6f 6d 70 6c 65 74 65 64 } //1 faf Completed
		$a_81_6 = {64 61 73 64 73 66 64 64 6c 65 74 65 64 } //1 dasdsfddleted
		$a_81_7 = {64 61 66 70 6c 65 74 65 64 } //1 dafpleted
		$a_81_8 = {64 66 70 6c 65 74 65 64 } //1 dfpleted
		$a_81_9 = {64 61 73 64 73 61 64 20 43 6f 6d 70 6c 65 74 65 64 } //1 dasdsad Completed
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}