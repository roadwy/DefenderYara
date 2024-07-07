
rule Trojan_MacOS_WireLurker_D_MTB{
	meta:
		description = "Trojan:MacOS/WireLurker.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 74 6d 70 2f 74 2e 6c 6f 63 6b } //1 /tmp/t.lock
		$a_00_1 = {2f 62 69 6e 2f 6c 61 75 6e 63 68 63 74 6c 20 6c 6f 61 64 20 2d 77 46 20 2f 53 79 73 74 65 6d 2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 44 61 65 6d 6f 6e 73 2f 63 6f 6d 2e 61 70 70 6c 65 2e 4d 61 69 6c 53 65 72 76 69 63 65 41 67 65 6e 74 48 65 6c 70 65 72 2e 70 6c 69 73 74 } //1 /bin/launchctl load -wF /System/Library/LaunchDaemons/com.apple.MailServiceAgentHelper.plist
		$a_00_2 = {73 79 73 74 65 6d 6b 65 79 63 68 61 69 6e 2d 68 65 6c 70 65 72 } //1 systemkeychain-helper
		$a_00_3 = {2f 74 6d 70 2f 75 70 2f 75 70 64 61 74 65 2e 7a 69 70 } //1 /tmp/up/update.zip
		$a_00_4 = {2f 75 73 72 2f 73 68 61 72 65 2f 74 6f 6b 65 6e 69 7a 65 72 2f 6a 61 } //1 /usr/share/tokenizer/ja
		$a_00_5 = {63 6f 6d 2e 61 70 70 6c 65 2e 61 70 70 73 74 6f 72 65 2e 50 6c 75 67 69 6e 48 65 6c 70 65 72 } //1 com.apple.appstore.PluginHelper
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}