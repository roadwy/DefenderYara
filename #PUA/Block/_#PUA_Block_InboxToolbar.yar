
rule _#PUA_Block_InboxToolbar{
	meta:
		description = "!#PUA:Block:InboxToolbar,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_81_0 = {49 6e 62 6f 78 20 4d 61 70 73 20 54 6f 6f 6c 62 61 72 } //1 Inbox Maps Toolbar
		$a_81_1 = {32 34 78 37 48 65 6c 70 } //1 24x7Help
		$a_81_2 = {47 65 74 20 43 61 73 68 20 42 61 63 6b 20 77 69 74 68 20 46 72 65 65 20 52 65 62 61 74 65 49 6e 66 6f 72 6d 65 72 } //1 Get Cash Back with Free RebateInformer
		$a_81_3 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_4 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*-100+(#a_81_4  & 1)*-100) >=3
 
}
rule _#PUA_Block_InboxToolbar_2{
	meta:
		description = "!#PUA:Block:InboxToolbar,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {49 6e 62 6f 78 20 54 6f 6f 6c 62 61 72 } //Inbox Toolbar  1
		$a_80_1 = {74 6f 6f 6c 62 61 72 2e 69 6e 62 6f 78 2e 63 6f 6d } //toolbar.inbox.com  1
		$a_80_2 = {50 43 50 6f 77 65 72 53 70 65 65 64 53 65 74 75 70 2e 65 78 65 } //PCPowerSpeedSetup.exe  1
		$a_80_3 = {4f 6e 6c 69 6e 65 56 61 75 6c 74 } //OnlineVault  1
		$a_80_4 = {43 72 61 77 6c 65 72 20 54 6f 6f 6c 62 61 72 } //Crawler Toolbar  1
		$a_80_5 = {63 72 61 77 6c 65 72 2e 63 6f 6d } //crawler.com  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}
rule _#PUA_Block_InboxToolbar_3{
	meta:
		description = "!#PUA:Block:InboxToolbar,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_81_0 = {4d 61 70 73 20 54 6f 6f 6c 62 61 72 20 50 6f 77 65 72 65 64 20 62 79 20 49 6e 62 6f 78 } //1 Maps Toolbar Powered by Inbox
		$a_81_1 = {32 34 78 37 48 65 6c 70 } //1 24x7Help
		$a_81_2 = {50 43 20 50 6f 77 65 72 20 53 70 65 65 64 } //1 PC Power Speed
		$a_81_3 = {4f 6e 6c 69 6e 65 20 56 61 75 6c 74 } //1 Online Vault
		$a_81_4 = {41 70 70 47 72 61 66 66 69 74 69 } //1 AppGraffiti
		$a_81_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_6 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*-100+(#a_81_6  & 1)*-100) >=5
 
}
rule _#PUA_Block_InboxToolbar_4{
	meta:
		description = "!#PUA:Block:InboxToolbar,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_81_0 = {49 6e 62 6f 78 20 45 6d 61 69 6c 4e 6f 74 69 66 69 65 72 20 54 6f 6f 6c 62 61 72 } //1 Inbox EmailNotifier Toolbar
		$a_81_1 = {32 34 78 37 48 65 6c 70 } //1 24x7Help
		$a_81_2 = {50 43 20 50 6f 77 65 72 20 53 70 65 65 64 } //1 PC Power Speed
		$a_81_3 = {4f 6e 6c 69 6e 65 20 56 61 75 6c 74 } //1 Online Vault
		$a_81_4 = {47 65 74 20 43 61 73 68 20 42 61 63 6b 20 77 69 74 68 20 46 72 65 65 20 52 65 62 61 74 65 49 6e 66 6f 72 6d 65 72 } //1 Get Cash Back with Free RebateInformer
		$a_81_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_6 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*-100+(#a_81_6  & 1)*-100) >=5
 
}
rule _#PUA_Block_InboxToolbar_5{
	meta:
		description = "!#PUA:Block:InboxToolbar,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_81_0 = {49 6e 62 6f 78 20 54 6f 6f 6c 62 61 72 } //1 Inbox Toolbar
		$a_81_1 = {49 6e 62 6f 78 20 50 75 62 6c 69 63 20 54 72 61 6e 73 70 6f 72 74 20 54 6f 6f 6c 62 61 72 } //1 Inbox Public Transport Toolbar
		$a_81_2 = {32 34 78 37 48 65 6c 70 } //1 24x7Help
		$a_81_3 = {50 43 20 50 6f 77 65 72 20 53 70 65 65 64 } //1 PC Power Speed
		$a_81_4 = {47 65 74 20 43 61 73 68 20 42 61 63 6b 20 77 69 74 68 20 46 72 65 65 20 52 65 62 61 74 65 49 6e 66 6f 72 6d 65 72 } //1 Get Cash Back with Free RebateInformer
		$a_81_5 = {41 70 70 47 72 61 66 66 69 74 69 } //1 AppGraffiti
		$a_81_6 = {55 6e 69 6e 73 74 2e 65 78 65 } //-100 Uninst.exe
		$a_81_7 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //-100 Uninstall.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*-100+(#a_81_7  & 1)*-100) >=6
 
}