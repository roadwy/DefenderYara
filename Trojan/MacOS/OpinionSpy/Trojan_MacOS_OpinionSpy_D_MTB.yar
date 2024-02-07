
rule Trojan_MacOS_OpinionSpy_D_MTB{
	meta:
		description = "Trojan:MacOS/OpinionSpy.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 73 63 6f 72 65 2f 77 6f 72 6b 69 6e 67 63 6f 70 79 2f 4d 61 63 53 6e 69 66 66 65 72 } //01 00  comscore/workingcopy/MacSniffer
		$a_00_1 = {49 6e 6a 65 63 74 43 6f 64 65 2e 61 70 70 2f 43 6f 6e 74 65 6e 74 73 2f 52 65 73 6f 75 72 63 65 73 2f 6d 61 63 6d 65 74 65 72 68 6b 2e 62 75 6e 64 6c 65 } //01 00  InjectCode.app/Contents/Resources/macmeterhk.bundle
		$a_00_2 = {61 70 70 2f 43 6f 6e 74 65 6e 74 73 2f 52 65 73 6f 75 72 63 65 73 2f 6d 61 63 6d 65 74 65 72 50 64 66 } //01 00  app/Contents/Resources/macmeterPdf
		$a_00_3 = {6f 73 73 70 72 6f 78 79 2e 65 78 65 } //01 00  ossproxy.exe
		$a_00_4 = {72 75 6c 65 73 2e 73 65 63 75 72 65 73 74 75 64 69 65 73 2e 63 6f 6d } //00 00  rules.securestudies.com
		$a_00_5 = {5d 04 00 00 } //fb 07 
	condition:
		any of ($a_*)
 
}