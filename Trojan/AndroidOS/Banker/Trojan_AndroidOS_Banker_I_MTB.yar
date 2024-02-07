
rule Trojan_AndroidOS_Banker_I_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {67 72 70 70 6c 2e 61 6e 64 72 6f 69 64 2e 73 68 65 6c 6c 2e 43 4d 42 6c 6c 6f 79 64 73 54 53 42 37 33 } //01 00  grppl.android.shell.CMBlloydsTSB73
		$a_00_1 = {68 74 73 75 2e 68 73 62 63 70 65 72 73 6f 6e 61 6c 62 61 6e 6b 69 6e 67 } //01 00  htsu.hsbcpersonalbanking
		$a_00_2 = {6c 61 62 61 6e 71 75 65 70 6f 73 74 61 6c 65 2e 61 63 63 6f 75 6e 74 61 63 63 65 73 73 } //01 00  labanquepostale.accountaccess
		$a_00_3 = {74 72 61 63 6b 67 6f 6f 67 6c 65 2e 61 74 2f 61 6e 67 65 6c 6b 65 6c 6c 79 } //01 00  trackgoogle.at/angelkelly
		$a_00_4 = {2f 64 65 76 2f 63 70 75 63 74 6c 2f 74 61 73 6b 73 } //01 00  /dev/cpuctl/tasks
		$a_00_5 = {74 73 62 2e 6d 6f 62 69 6c 65 62 61 6e 6b } //00 00  tsb.mobilebank
		$a_00_6 = {5d 04 00 00 26 } //8c 04 
	condition:
		any of ($a_*)
 
}