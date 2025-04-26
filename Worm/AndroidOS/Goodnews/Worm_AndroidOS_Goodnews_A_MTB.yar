
rule Worm_AndroidOS_Goodnews_A_MTB{
	meta:
		description = "Worm:AndroidOS/Goodnews.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 79 57 68 61 74 73 61 70 70 43 6f 6e 74 61 63 74 73 4e 6f } //1 myWhatsappContactsNo
		$a_00_1 = {61 48 52 30 63 44 6f 76 4c 33 52 70 62 6e 6b 75 59 32 4d } //1 aHR0cDovL3RpbnkuY2M
		$a_00_2 = {63 6f 6d 2e 73 65 65 2e 63 6f 77 69 6e 68 65 6c 70 } //1 com.see.cowinhelp
		$a_00_3 = {43 6f 57 49 4e 20 52 65 67 69 73 74 72 61 74 69 6f 6e 20 50 72 6f 63 65 73 73 } //1 CoWIN Registration Process
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}