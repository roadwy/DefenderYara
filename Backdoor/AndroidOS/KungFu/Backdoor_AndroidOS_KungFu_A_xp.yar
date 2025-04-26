
rule Backdoor_AndroidOS_KungFu_A_xp{
	meta:
		description = "Backdoor:AndroidOS/KungFu.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {42 03 d0 05 23 5b 42 08 93 d3 e7 30 1c 29 1c ff f7 09 ff 08 } //1
		$a_00_1 = {2f 73 79 73 74 65 6d 2f 65 74 63 2f 2e 72 69 6c 64 5f 63 66 67 } //1 /system/etc/.rild_cfg
		$a_00_2 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 70 6d 20 69 6e 73 74 61 6c 6c 20 2d 72 } //1 /system/bin/pm install -r
		$a_00_3 = {6f 6b 6e 6f 6c 6f 63 6b } //1 oknolock
		$a_00_4 = {2f 73 79 73 74 65 6d 2f 62 69 6e 2f 70 6d 20 75 6e 69 6e 73 74 61 6c 6c } //1 /system/bin/pm uninstall
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}