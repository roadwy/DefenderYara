
rule Trojan_AndroidOS_Spynote_E{
	meta:
		description = "Trojan:AndroidOS/Spynote.E,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 6f 6f 74 40 } //01 00  root@
		$a_00_1 = {43 61 6e 27 74 20 67 65 74 20 6c 6f 63 61 74 69 6f 6e 20 62 79 20 61 6e 79 20 6f 6e 65 } //01 00  Can't get location by any one
		$a_01_2 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 73 63 72 65 65 6e 63 61 70 20 2d 70 20 2f 73 64 63 61 72 64 2f 72 6f 6f 74 53 55 2e 70 6e 67 } //00 00  /system/bin/screencap -p /sdcard/rootSU.png
	condition:
		any of ($a_*)
 
}