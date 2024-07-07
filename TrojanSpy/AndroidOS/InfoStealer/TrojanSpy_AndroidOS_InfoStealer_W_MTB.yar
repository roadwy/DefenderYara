
rule TrojanSpy_AndroidOS_InfoStealer_W_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/InfoStealer.W!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {2f 77 65 62 70 72 6f 6a 65 63 74 90 02 02 2f 44 6f 77 6e 6c 6f 61 64 43 6f 6d 70 6c 65 74 65 52 65 63 65 69 76 65 72 3b 90 00 } //1
		$a_01_1 = {2f 69 6e 64 65 78 2e 70 68 70 2f 41 70 69 2f 50 75 62 6c 69 63 2f 61 64 64 5f 61 64 64 72 65 73 73 5f 62 6f 6f 6b } //1 /index.php/Api/Public/add_address_book
		$a_01_2 = {73 65 6e 64 43 6f 6e 74 61 63 74 54 6f 53 65 72 76 65 72 } //1 sendContactToServer
		$a_01_3 = {75 70 6c 6f 61 64 4d 65 73 73 61 67 65 41 62 6f 76 65 4c } //1 uploadMessageAboveL
		$a_01_4 = {2f 68 35 3f 70 6c 61 74 3d 61 6e 64 72 6f 69 64 } //1 /h5?plat=android
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}