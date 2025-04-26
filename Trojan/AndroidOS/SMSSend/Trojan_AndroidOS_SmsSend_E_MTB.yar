
rule Trojan_AndroidOS_SmsSend_E_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsSend.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 61 67 65 77 61 70 2f 65 72 6f 2f 67 61 6c 6c 65 72 79 2f 47 61 6c 6c 65 72 79 41 63 74 69 76 69 74 79 } //1 com/agewap/ero/gallery/GalleryActivity
		$a_01_1 = {73 65 6e 64 54 65 78 74 4d 65 73 73 61 67 65 } //1 sendTextMessage
		$a_01_2 = {66 69 6c 65 2e 6c 6f 63 6b } //1 file.lock
		$a_01_3 = {2f 49 6d 61 67 65 41 64 61 70 74 65 72 } //1 /ImageAdapter
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}