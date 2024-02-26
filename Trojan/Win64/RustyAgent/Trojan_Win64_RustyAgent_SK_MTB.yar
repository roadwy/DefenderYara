
rule Trojan_Win64_RustyAgent_SK_MTB{
	meta:
		description = "Trojan:Win64/RustyAgent.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {22 2c 22 74 63 22 3a 22 54 43 22 2c 22 6e 72 22 3a } //01 00  ","tc":"TC","nr":
		$a_81_1 = {57 69 6e 64 6f 77 73 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 52 75 6e 30 30 72 73 74 } //01 00  WindowsCurrentVersionRun00rst
		$a_81_2 = {72 75 73 74 5f 70 61 6e 69 63 } //01 00  rust_panic
		$a_81_3 = {72 73 74 4d 59 50 41 54 48 } //00 00  rstMYPATH
	condition:
		any of ($a_*)
 
}