
rule Trojan_Win64_T1557_AdversaryInTheMiddle_A{
	meta:
		description = "Trojan:Win64/T1557_AdversaryInTheMiddle.A,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {73 00 65 00 6b 00 75 00 72 00 6c 00 73 00 61 00 3a 00 3a 00 70 00 74 00 68 00 } //0a 00  sekurlsa::pth
		$a_01_1 = {6d 00 69 00 73 00 63 00 3a 00 3a 00 65 00 66 00 73 00 } //00 00  misc::efs
	condition:
		any of ($a_*)
 
}