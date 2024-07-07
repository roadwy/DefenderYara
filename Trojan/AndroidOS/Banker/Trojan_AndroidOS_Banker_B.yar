
rule Trojan_AndroidOS_Banker_B{
	meta:
		description = "Trojan:AndroidOS/Banker.B,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 6e 64 72 6f 64 4d 6f 64 65 } //1 AndrodMode
		$a_01_1 = {55 52 4c 5f 41 50 50 4c 4f 47 53 } //1 URL_APPLOGS
		$a_01_2 = {73 65 6e 64 53 6d 73 74 6f 65 72 76 65 72 } //1 sendSmstoerver
		$a_01_3 = {6d 79 41 70 70 3a 77 61 6b 65 75 6e 6c 6f 63 6b 65 72 } //1 myApp:wakeunlocker
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}