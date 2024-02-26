
rule Trojan_MacOS_DownloadAgent_A{
	meta:
		description = "Trojan:MacOS/DownloadAgent.A,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {73 75 64 6f 20 69 6e 73 74 61 6c 6c 65 72 20 2d 70 6b 67 20 2f 74 6d 70 2f 70 79 74 68 6f 6e 90 02 20 2e 70 6b 67 20 2d 74 61 72 67 65 74 90 02 20 3c 3f 78 6d 6c 90 00 } //01 00 
		$a_00_1 = {73 75 62 70 72 6f 63 65 73 73 2e 63 61 6c 6c 28 5b 27 6b 69 6c 6c 61 6c 6c 27 2c 20 27 4e 6f 74 69 66 69 63 61 74 69 6f 6e 43 65 6e 74 65 72 27 5d 29 } //01 00  subprocess.call(['killall', 'NotificationCenter'])
		$a_00_2 = {73 70 63 74 6c 20 2d 2d 6d 61 73 74 65 72 2d 64 69 73 61 62 6c 65 } //01 00  spctl --master-disable
		$a_00_3 = {69 6d 6f 00 6a 61 6e 65 00 66 65 65 64 00 76 6f 61 00 64 61 61 69 6c 79 00 72 6f 6e 67 00 61 70 70 00 6e 65 77 73 00 68 75 62 } //01 00  浩o慪敮昀敥d潶a慤楡祬爀湯g灡p敮獷栀扵
		$a_02_4 = {25 40 2e 25 73 25 73 2e 6e 65 74 90 02 20 54 68 65 20 68 61 73 68 65 73 20 61 72 65 20 74 68 65 20 73 61 6d 65 2e 90 00 } //00 00 
		$a_00_5 = {5d 04 00 } //00 10 
	condition:
		any of ($a_*)
 
}