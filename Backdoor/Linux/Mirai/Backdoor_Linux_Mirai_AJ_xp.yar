
rule Backdoor_Linux_Mirai_AJ_xp{
	meta:
		description = "Backdoor:Linux/Mirai.AJ!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 76 61 72 2f 74 6d 70 2f 73 6f 6e 69 61 } //01 00  /var/tmp/sonia
		$a_01_1 = {2f 64 65 76 2f 46 54 57 44 54 31 30 31 5f 77 61 74 63 68 64 6f 67 } //02 00  /dev/FTWDT101_watchdog
		$a_01_2 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 } //01 00  /bin/busybox chmod 777
		$a_01_3 = {2f 64 65 76 2f 6e 65 74 73 6c 69 6e 6b 2f } //01 00  /dev/netslink/
		$a_01_4 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 72 6d 20 2d 72 66 20 2e 66 69 6c 65 } //01 00  /bin/busybox rm -rf .file
		$a_01_5 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //00 00  npxXoudifFeEgGaACScs
		$a_00_6 = {5d 04 00 00 } //76 15 
	condition:
		any of ($a_*)
 
}