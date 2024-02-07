
rule Backdoor_MacOS_Wirelurker_A{
	meta:
		description = "Backdoor:MacOS/Wirelurker.A,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 75 6e 2e 73 68 00 2f 75 73 72 2f 6c 6f 63 61 6c 2f 6d 61 63 68 6f 6f 6b 2f 6d 61 63 68 6f 6f 6b 00 } //01 00 
		$a_00_1 = {46 6f 6e 74 4d 61 70 31 2e 63 66 67 00 2f 62 69 6e 2f 73 68 00 2d 72 66 00 2f 55 73 65 72 73 2f 53 68 61 72 65 64 2f 73 74 61 72 74 2e 73 68 00 } //01 00  潆瑮慍ㅰ挮杦⼀楢⽮桳ⴀ晲⼀獕牥⽳桓牡摥猯慴瑲献h
		$a_02_2 = {2e 67 6c 6f 62 61 6c 75 70 64 61 74 65 2e 70 6c 69 73 74 00 6e 6f 00 79 65 73 00 68 74 74 70 3a 2f 2f 77 77 77 2e 90 02 1e 2e 63 6f 6d 2f 6d 61 63 5f 6c 6f 67 2f 3f 61 70 70 69 64 3d 25 40 2b 2b 25 40 2b 2b 25 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_MacOS_Wirelurker_A_2{
	meta:
		description = "Backdoor:MacOS/Wirelurker.A,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {2f 44 65 72 69 76 65 64 44 61 74 61 2f 6d 79 50 72 6f 6a 65 63 74 2d 62 65 6d 70 6e 75 75 6e 79 73 78 6f 61 66 63 64 65 6f 6b 75 76 76 66 69 67 6d 7a 65 2f } //01 00  /DerivedData/myProject-bempnuunysxoafcdeokuvvfigmze/
		$a_00_1 = {2f 53 79 73 74 65 6d 2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 44 61 65 6d 6f 6e 73 2f 63 6f 6d 2e 61 70 70 6c 65 2e 4d 61 69 6c 53 65 72 76 69 63 65 41 67 65 6e 74 48 65 6c 70 65 72 2e 70 6c 69 73 74 } //01 00  /System/Library/LaunchDaemons/com.apple.MailServiceAgentHelper.plist
		$a_00_2 = {72 6d 20 2d 72 66 20 2f 76 61 72 2f 64 62 2f 6c 61 75 6e 63 68 64 2e 64 62 2f 63 6f 6d 2e 61 70 70 6c 65 2e 6c 61 75 6e 63 68 64 2f } //00 00  rm -rf /var/db/launchd.db/com.apple.launchd/
	condition:
		any of ($a_*)
 
}