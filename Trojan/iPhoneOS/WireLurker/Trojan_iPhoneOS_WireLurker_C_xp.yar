
rule Trojan_iPhoneOS_WireLurker_C_xp{
	meta:
		description = "Trojan:iPhoneOS/WireLurker.C!xp,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {77 77 77 2e 63 6f 6d 65 69 6e 62 61 62 79 2e 63 6f 6d } //2 www.comeinbaby.com
		$a_00_1 = {2f 6d 61 63 2f 67 65 74 76 65 72 73 69 6f 6e 2e 70 68 70 } //1 /mac/getversion.php
		$a_00_2 = {2f 75 70 64 61 74 65 2f 75 70 64 61 74 65 2e 7a 69 70 } //1 /update/update.zip
		$a_00_3 = {2f 75 73 72 2f 6c 6f 63 61 6c 2f 6d 61 63 68 6f 6f 6b 2f 77 61 74 63 68 2e 73 68 } //1 /usr/local/machook/watch.sh
		$a_00_4 = {6b 69 6c 6c 20 2d 48 55 50 20 53 70 72 69 6e 67 42 6f 61 72 64 } //1 kill -HUP SpringBoard
		$a_00_5 = {73 74 61 72 74 5f 6c 6f 67 2f 3f 61 70 70 3d 25 40 26 73 6e 3d 25 40 } //1 start_log/?app=%@&sn=%@
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}