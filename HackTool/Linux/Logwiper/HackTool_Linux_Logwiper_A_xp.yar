
rule HackTool_Linux_Logwiper_A_xp{
	meta:
		description = "HackTool:Linux/Logwiper.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 76 61 72 2f 72 75 6e 2f 75 74 6d 70 } //1 /var/run/utmp
		$a_01_1 = {2f 74 6d 70 2f 55 54 4d 50 2e 54 4d 50 } //1 /tmp/UTMP.TMP
		$a_01_2 = {6c 61 73 74 6c 6f 67 5f 63 6c 65 61 6e } //1 lastlog_clean
		$a_01_3 = {6d 69 67 2d 6c 6f 67 63 6c 65 61 6e 65 72 2e 63 } //1 mig-logcleaner.c
		$a_01_4 = {63 68 6d 6f 64 20 2b 78 20 2f 74 6d 70 2f 6d 69 67 2e 73 68 } //1 chmod +x /tmp/mig.sh
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}