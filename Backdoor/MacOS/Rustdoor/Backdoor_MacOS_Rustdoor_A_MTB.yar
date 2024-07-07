
rule Backdoor_MacOS_Rustdoor_A_MTB{
	meta:
		description = "Backdoor:MacOS/Rustdoor.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {70 72 6f 67 72 61 6d 73 72 63 2f 70 65 72 73 69 73 74 65 6e 63 65 2e 72 73 2f 55 73 65 72 73 2f 2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2e 70 6c 69 73 74 46 61 69 6c 65 64 } //1 programsrc/persistence.rs/Users//Library/LaunchAgents.plistFailed
		$a_00_1 = {4c 61 75 6e 63 68 63 74 6c 73 72 63 2f 68 74 74 70 2e 72 73 67 61 74 65 77 61 79 2f 74 61 73 6b 74 61 73 6b 73 2f 75 70 6c 6f } //1 Launchctlsrc/http.rsgateway/tasktasks/uplo
		$a_00_2 = {6c 69 62 2e 72 73 6c 61 75 6e 63 68 63 74 6c 75 6e 6c 6f 61 64 2d 77 46 61 69 6c 65 64 } //1 lib.rslaunchctlunload-wFailed
		$a_00_3 = {68 6f 73 74 6e 61 6d 65 2d 63 6f 6d 6d 61 6e 64 74 65 6d 70 2e 7a 69 70 74 61 73 6b 6b 69 6c 6c 64 6f 77 6e 6c 6f 61 64 } //1 hostname-commandtemp.ziptaskkilldownload
		$a_00_4 = {70 73 73 68 65 6c 6c 63 64 6d 6b 64 69 72 72 6d 72 6d 64 69 72 73 6c 65 65 70 75 70 6c 6f 61 64 62 6f 74 6b 69 6c 6c 45 72 72 6f 72 } //1 psshellcdmkdirrmrmdirsleepuploadbotkillError
		$a_00_5 = {70 6b 69 6c 6c 2d 31 35 63 6f 6d 2e 61 70 70 6c 65 2e 64 6f 63 6b 70 65 72 73 69 73 74 65 6e 74 2d 61 70 70 73 } //1 pkill-15com.apple.dockpersistent-apps
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}