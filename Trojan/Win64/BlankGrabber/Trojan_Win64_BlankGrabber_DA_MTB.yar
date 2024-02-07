
rule Trojan_Win64_BlankGrabber_DA_MTB{
	meta:
		description = "Trojan:Win64/BlankGrabber.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 6c 61 6e 6b 47 72 61 62 62 65 72 } //01 00  BlankGrabber
		$a_01_1 = {54 61 6b 69 6e 67 20 73 63 72 65 65 6e 73 68 6f 74 } //01 00  Taking screenshot
		$a_01_2 = {77 69 66 69 20 70 61 73 73 77 6f 72 64 73 } //01 00  wifi passwords
		$a_01_3 = {50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //01 00  Passwords.txt
		$a_01_4 = {42 6c 6f 63 6b 69 6e 67 20 41 56 20 73 69 74 65 73 } //01 00  Blocking AV sites
		$a_01_5 = {49 6e 6a 65 63 74 69 6e 67 20 62 61 63 6b 64 6f 6f 72 } //00 00  Injecting backdoor
	condition:
		any of ($a_*)
 
}