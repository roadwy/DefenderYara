
rule Trojan_BAT_XWorm_SG_MTB{
	meta:
		description = "Trojan:BAT/XWorm.SG!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 00 72 00 6c 00 68 00 69 00 64 00 65 00 } //1 Urlhide
		$a_01_1 = {73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 2e 00 65 00 78 00 65 00 20 00 2d 00 4c 00 } //1 shutdown.exe -L
		$a_01_2 = {52 00 75 00 6e 00 53 00 68 00 65 00 6c 00 6c 00 } //1 RunShell
		$a_01_3 = {4f 00 66 00 66 00 6c 00 69 00 6e 00 65 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 4e 00 6f 00 74 00 20 00 45 00 6e 00 61 00 62 00 6c 00 65 00 64 00 } //1 OfflineKeylogger Not Enabled
		$a_01_4 = {2f 00 64 00 65 00 76 00 2f 00 64 00 69 00 73 00 6b 00 2f 00 62 00 79 00 2d 00 75 00 75 00 69 00 64 00 } //1 /dev/disk/by-uuid
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}