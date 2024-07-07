
rule Trojan_AndroidOS_Spynote_E{
	meta:
		description = "Trojan:AndroidOS/Spynote.E,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 6f 6f 74 40 } //1 root@
		$a_00_1 = {43 61 6e 27 74 20 67 65 74 20 6c 6f 63 61 74 69 6f 6e 20 62 79 20 61 6e 79 20 6f 6e 65 } //1 Can't get location by any one
		$a_01_2 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 73 63 72 65 65 6e 63 61 70 20 2d 70 20 2f 73 64 63 61 72 64 2f 72 6f 6f 74 53 55 2e 70 6e 67 } //1 /system/bin/screencap -p /sdcard/rootSU.png
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_AndroidOS_Spynote_E_2{
	meta:
		description = "Trojan:AndroidOS/Spynote.E,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {74 68 69 73 20 61 70 70 20 64 6f 65 73 20 6e 6f 74 20 73 75 70 70 6f 72 74 20 65 6d 75 6c 61 74 6f 72 20 64 65 76 69 63 65 73 } //1 this app does not support emulator devices
		$a_01_1 = {74 6f 20 41 6c 6c 6f 77 20 61 70 70 2c 20 64 69 73 61 62 6c 65 20 66 69 72 65 77 61 6c 6c 20 66 69 72 73 74 2e } //1 to Allow app, disable firewall first.
		$a_01_2 = {43 6c 69 63 6b 3a 20 5b 44 65 6c 65 74 65 5d } //1 Click: [Delete]
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}