
rule Backdoor_MacOS_Longage_A{
	meta:
		description = "Backdoor:MacOS/Longage.A,SIGNATURE_TYPE_MACHOHSTR_EXT,0e 00 0c 00 0a 00 00 05 00 "
		
	strings :
		$a_01_0 = {4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2f 00 } //05 00  楌牢牡⽹慌湵档杁湥獴/
		$a_01_1 = {63 6f 6d 2e 61 70 70 6c 65 2e 46 6f 6c 64 65 72 41 63 74 69 6f 6e 73 78 6c 2e 70 6c 69 73 74 00 } //02 00 
		$a_00_2 = {77 72 69 74 65 74 6f 66 69 6c 65 } //02 00  writetofile
		$a_00_3 = {63 6f 70 79 73 65 6c 66 } //02 00  copyself
		$a_00_4 = {72 65 6d 6f 74 65 20 73 68 65 6c 6c } //02 00  remote shell
		$a_00_5 = {67 65 74 20 63 6f 6e 66 69 67 } //02 00  get config
		$a_00_6 = {72 75 6e 61 74 6c 6f 61 64 } //e2 ff  runatload
		$a_00_7 = {4f 53 58 2f 4d 61 63 4b 6f 6e 74 72 6f 6c 2e 41 } //e2 ff  OSX/MacKontrol.A
		$a_00_8 = {6d 61 67 69 63 61 6e 73 6f 66 74 2e 63 6f 6d 2f 6d 61 67 69 63 61 6e 5f 73 6f 66 74 5f 75 70 67 72 61 64 65 5f 66 69 6c 65 73 2f 61 6e 74 69 74 72 6f 6a 61 6e 75 70 64 61 74 65 2f } //e2 ff  magicansoft.com/magican_soft_upgrade_files/antitrojanupdate/
		$a_00_9 = {70 72 6f 66 69 6c 65 72 2f 65 6c 74 2f 73 6c 6f 77 70 61 74 68 65 6c 74 6c 65 61 76 65 2f 73 6c 6f 77 70 61 74 68 65 6c 74 6c 65 61 76 65 } //00 00  profiler/elt/slowpatheltleave/slowpatheltleave
	condition:
		any of ($a_*)
 
}