
rule Trojan_AndroidOS_HiddenApp_E_MTB{
	meta:
		description = "Trojan:AndroidOS/HiddenApp.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {61 61 61 70 70 73 2e 6c 69 73 74 2e 63 6f 6d 2e 74 61 6b 65 6e 6f 74 65 } //1 aaapps.list.com.takenote
		$a_00_1 = {4e 6f 74 65 44 65 74 61 69 6c 73 45 64 69 74 41 63 74 69 76 69 74 79 } //1 NoteDetailsEditActivity
		$a_00_2 = {67 6f 6f 2e 67 6c 2f 4a 78 58 79 5a 49 } //1 goo.gl/JxXyZI
		$a_00_3 = {48 69 64 64 65 6e 42 79 41 70 70 } //1 HiddenByApp
		$a_00_4 = {63 6f 6d 2e 70 75 73 73 6c 69 65 73 2e 6f 6e 61 67 72 61 2e 4d 6f 64 65 43 68 61 6e 67 65 64 52 65 63 65 69 76 65 72 } //1 com.pusslies.onagra.ModeChangedReceiver
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}