
rule Trojan_AndroidOS_Opfake_D_MTB{
	meta:
		description = "Trojan:AndroidOS/Opfake.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 6d 6c 2f 61 6e 64 72 6f 69 64 2f 69 6e 73 74 61 6c 6c 2f 44 6f 77 6e 6c 6f 61 64 } //2 html/android/install/Download
		$a_01_1 = {2f 48 74 6d 6c 53 4d 53 41 63 74 69 76 69 74 79 } //2 /HtmlSMSActivity
		$a_01_2 = {72 65 61 64 4f 70 74 69 6f 6e 73 58 6d 6c } //1 readOptionsXml
		$a_01_3 = {67 6f 4d 65 73 73 61 67 65 } //1 goMessage
		$a_01_4 = {73 65 6e 64 54 65 78 74 4d 65 73 73 61 67 65 } //1 sendTextMessage
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}