
rule Ransom_Linux_NoEscape_A_MTB{
	meta:
		description = "Ransom:Linux/NoEscape.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {48 4f 57 5f 54 4f 5f 52 45 43 4f 56 45 52 5f 46 49 4c 45 53 2e 74 78 74 } //1 HOW_TO_RECOVER_FILES.txt
		$a_00_1 = {69 6d 67 70 61 79 6c 64 2e 74 67 7a } //1 imgpayld.tgz
		$a_00_2 = {63 61 6c 6c 69 6e 67 20 69 6f 63 74 6c 73 6f 63 6b 65 74 } //1 calling ioctlsocket
		$a_00_3 = {6e 6f 74 65 5f 74 65 78 74 } //1 note_text
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}