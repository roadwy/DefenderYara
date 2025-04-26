
rule Trojan_MacOS_Rustbucket_AP{
	meta:
		description = "Trojan:MacOS/Rustbucket.AP,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {64 6f 77 6e 41 6e 64 45 78 65 63 75 74 65 } //1 downAndExecute
		$a_00_1 = {63 6f 6d 2e 61 70 70 6c 65 2e 70 64 66 56 69 65 77 65 72 } //1 com.apple.pdfViewer
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}