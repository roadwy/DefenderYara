
rule TrojanDownloader_Win32_Agent_ABHL{
	meta:
		description = "TrojanDownloader:Win32/Agent.ABHL,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 53 4d 53 31 30 30 30 4d 61 69 6e 5c 68 74 6d 6c 5c } //01 00  \SMS1000Main\html\
		$a_01_1 = {5c 53 4d 53 31 30 30 30 55 70 64 61 74 65 5c 48 73 41 63 } //01 00  \SMS1000Update\HsAc
		$a_01_2 = {2e 73 6d 73 31 30 30 30 2e 63 6f 2e 6b 72 2f 41 70 70 2f 75 70 61 70 70 2f } //01 00  .sms1000.co.kr/App/upapp/
		$a_01_3 = {43 6f 6e 74 72 6f 6c 4e 6f 74 69 66 69 65 72 2f 6e 65 77 61 67 72 65 65 2e 64 61 74 } //00 00  ControlNotifier/newagree.dat
	condition:
		any of ($a_*)
 
}