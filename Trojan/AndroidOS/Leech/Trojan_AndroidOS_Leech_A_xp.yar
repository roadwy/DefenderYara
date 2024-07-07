
rule Trojan_AndroidOS_Leech_A_xp{
	meta:
		description = "Trojan:AndroidOS/Leech.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 64 61 74 61 2f 6c 6f 63 61 6c 2f 74 6d 70 2f 77 61 74 63 68 64 6f 67 2e 70 69 64 } //1 /data/local/tmp/watchdog.pid
		$a_00_1 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 70 6d 20 75 6e 69 6e 73 74 61 6c 6c } //1 /system/bin/pm uninstall
		$a_00_2 = {67 65 74 5f 63 6f 6d 6d 61 6e 64 5f 69 6e 74 65 72 76 61 6c } //1 get_command_interval
		$a_00_3 = {2f 73 79 73 74 65 6d 2f 75 73 72 2f 2e 68 64 5f 72 65 63 6f 76 65 72 79 } //1 /system/usr/.hd_recovery
		$a_00_4 = {63 68 6d 6f 64 20 37 37 37 20 2f 73 79 73 74 65 6d 2f 61 70 70 2f 25 73 2e 61 70 6b } //1 chmod 777 /system/app/%s.apk
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}