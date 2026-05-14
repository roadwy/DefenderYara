
rule TrojanSpy_AndroidOS_Ghostchat_AMTB{
	meta:
		description = "TrojanSpy:AndroidOS/Ghostchat!AMTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 44 61 74 61 55 70 6c 6f 61 64 } //1 startDataUpload
		$a_01_1 = {73 63 68 65 64 75 6c 65 52 65 70 65 61 74 69 6e 67 55 70 6c 6f 61 64 } //1 scheduleRepeatingUpload
		$a_01_2 = {68 69 74 70 61 6b 2e 6f 72 67 } //2 hitpak.org
		$a_01_3 = {63 6f 6d 64 61 74 69 6e 67 62 61 74 63 68 63 68 61 74 61 70 70 43 68 61 74 41 63 74 69 76 69 74 79 } //2 comdatingbatchchatappChatActivity
		$a_01_4 = {73 63 61 6e 41 6e 64 55 70 6c 6f 61 64 4e 65 77 49 6d 61 67 65 73 } //1 scanAndUploadNewImages
		$a_01_5 = {75 70 6c 6f 61 64 43 6f 6e 74 61 63 74 73 } //2 uploadContacts
		$a_01_6 = {73 74 61 72 74 74 72 61 63 6b 69 6e 67 } //1 starttracking
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1) >=6
 
}