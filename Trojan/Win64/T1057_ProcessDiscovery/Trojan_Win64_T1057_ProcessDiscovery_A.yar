
rule Trojan_Win64_T1057_ProcessDiscovery_A{
	meta:
		description = "Trojan:Win64/T1057_ProcessDiscovery.A,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {73 00 65 00 6b 00 75 00 72 00 6c 00 73 00 61 00 3a 00 3a 00 6d 00 69 00 6e 00 69 00 64 00 75 00 6d 00 70 00 } //0a 00  sekurlsa::minidump
		$a_01_1 = {73 00 65 00 6b 00 75 00 72 00 6c 00 73 00 61 00 3a 00 3a 00 62 00 6f 00 6f 00 74 00 6b 00 65 00 79 00 } //0a 00  sekurlsa::bootkey
		$a_01_2 = {73 00 65 00 6b 00 75 00 72 00 6c 00 73 00 61 00 3a 00 3a 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //0a 00  sekurlsa::process
		$a_01_3 = {6d 00 69 00 73 00 63 00 3a 00 3a 00 64 00 65 00 74 00 6f 00 75 00 72 00 73 00 } //00 00  misc::detours
	condition:
		any of ($a_*)
 
}