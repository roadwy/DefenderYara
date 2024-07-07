
rule Trojan_AndroidOS_Dialer_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Dialer.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {79 6f 75 70 6f 72 6e 78 2e 68 6f 74 61 70 70 73 78 78 2e 63 6f 6d 2f 61 70 70 73 2f } //1 youpornx.hotappsxx.com/apps/
		$a_00_1 = {2f 75 74 69 6c 73 2f 43 61 6c 6c 44 75 72 61 74 69 6f 6e 52 65 63 65 69 76 65 72 3b } //1 /utils/CallDurationReceiver;
		$a_00_2 = {75 70 64 61 74 65 64 2e 61 70 6b } //1 updated.apk
		$a_00_3 = {6f 70 65 6e 5f 62 72 6f 77 73 65 72 } //1 open_browser
		$a_00_4 = {2f 64 65 73 63 61 72 67 61 2e 70 68 70 } //1 /descarga.php
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}