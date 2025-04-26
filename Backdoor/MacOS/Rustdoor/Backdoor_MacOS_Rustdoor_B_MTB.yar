
rule Backdoor_MacOS_Rustdoor_B_MTB{
	meta:
		description = "Backdoor:MacOS/Rustdoor.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 6b 69 6c 6c 2d 31 35 63 6f 6d 2e 61 70 70 6c 65 2e 64 6f 63 6b 70 65 72 73 69 73 74 65 6e 74 2d 61 70 70 73 } //1 pkill-15com.apple.dockpersistent-apps
		$a_00_1 = {2f 74 6d 70 2f 63 6f 6d 2e 61 70 70 6c 65 2e 6c 6f 63 6b 73 72 63 2f 63 72 6f 6e 2e 72 73 2f 63 72 6f 6e 2f 63 72 6f 6e 5f 61 73 6b 65 64 2f 76 61 72 2f 61 74 2f 74 61 62 73 2f } //1 /tmp/com.apple.locksrc/cron.rs/cron/cron_asked/var/at/tabs/
		$a_00_2 = {6c 69 62 2e 72 73 6c 61 75 6e 63 68 63 74 6c 75 6e 6c 6f 61 64 2d 77 46 61 69 6c 65 64 } //1 lib.rslaunchctlunload-wFailed
		$a_00_3 = {64 65 66 61 75 6c 74 73 2f 2e 70 61 73 73 77 64 68 6f 73 74 6e 61 6d 65 2d 63 6f 6d 6d 61 6e 64 74 61 73 6b 6b 69 6c 6c 64 6f 77 6e 6c 6f 61 64 } //1 defaults/.passwdhostname-commandtaskkilldownload
		$a_00_4 = {70 72 6f 67 72 61 6d 73 72 63 2f 70 65 72 73 69 73 74 65 6e 63 65 2e 72 73 2f 55 73 65 72 73 2f 2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2e 70 6c 69 73 74 73 72 63 } //1 programsrc/persistence.rs/Users//Library/LaunchAgents.plistsrc
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}