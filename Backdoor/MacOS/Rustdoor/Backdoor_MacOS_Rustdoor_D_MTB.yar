
rule Backdoor_MacOS_Rustdoor_D_MTB{
	meta:
		description = "Backdoor:MacOS/Rustdoor.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2f 2e 70 61 73 73 77 64 66 69 6c 65 2e 7a 69 70 68 6f 73 74 6e 61 6d 65 2d 63 6f 6d 6d 61 6e 64 74 61 73 6b 6b 69 6c 6c 64 6f 77 6e 6c 6f 61 64 } //1 /.passwdfile.ziphostname-commandtaskkilldownload
		$a_00_1 = {67 72 61 62 66 69 6c 65 73 2e 72 73 67 61 74 65 77 61 79 2f 72 65 67 69 73 74 65 72 63 68 65 63 6b 5f 63 72 6f 6e 5f 61 73 6b 65 64 } //1 grabfiles.rsgateway/registercheck_cron_asked
		$a_00_2 = {70 6c 69 73 74 70 6b 69 6c 6c 2d 31 35 63 6f 6d 2e 61 70 70 6c 65 2e 64 6f 63 6b 70 65 72 73 69 73 74 65 6e 74 2d 61 70 70 73 } //1 plistpkill-15com.apple.dockpersistent-apps
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}