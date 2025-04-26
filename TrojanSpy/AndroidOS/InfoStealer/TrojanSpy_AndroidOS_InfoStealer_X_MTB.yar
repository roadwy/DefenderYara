
rule TrojanSpy_AndroidOS_InfoStealer_X_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/InfoStealer.X!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 63 61 6f 2e 77 65 62 63 61 6d 65 72 61 } //1 com.cao.webcamera
		$a_01_1 = {79 6e 62 2e 67 7a 73 65 37 65 6e 2e 63 6f 6d } //1 ynb.gzse7en.com
		$a_01_2 = {2f 73 65 72 76 6c 65 74 2f 47 65 74 4d 65 73 73 61 67 65 } //1 /servlet/GetMessage
		$a_01_3 = {2f 73 65 72 76 6c 65 74 2f 53 65 6e 64 4d 61 73 73 61 67 65 4a 53 4f 4e } //1 /servlet/SendMassageJSON
		$a_01_4 = {2f 73 65 72 76 6c 65 74 2f 55 70 6c 6f 61 64 49 6d 61 67 65 } //1 /servlet/UploadImage
		$a_01_5 = {2f 73 65 72 76 6c 65 74 2f 43 6f 6e 74 61 63 74 73 55 70 6c 6f 61 64 } //1 /servlet/ContactsUpload
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}