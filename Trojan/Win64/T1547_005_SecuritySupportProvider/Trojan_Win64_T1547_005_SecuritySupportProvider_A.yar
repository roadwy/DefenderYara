
rule Trojan_Win64_T1547_005_SecuritySupportProvider_A{
	meta:
		description = "Trojan:Win64/T1547_005_SecuritySupportProvider.A,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6c 00 73 00 61 00 64 00 75 00 6d 00 70 00 3a 00 3a 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 73 00 } //0a 00  lsadump::packages
		$a_01_1 = {6d 00 69 00 73 00 63 00 3a 00 3a 00 6d 00 65 00 6d 00 73 00 73 00 70 00 } //0a 00  misc::memssp
		$a_01_2 = {6d 00 69 00 73 00 63 00 3a 00 3a 00 6c 00 6f 00 63 00 6b 00 } //0a 00  misc::lock
		$a_01_3 = {6d 00 69 00 73 00 63 00 3a 00 3a 00 70 00 72 00 69 00 6e 00 74 00 6e 00 69 00 67 00 68 00 74 00 6d 00 61 00 72 00 65 00 } //0a 00  misc::printnightmare
		$a_01_4 = {6d 00 69 00 73 00 63 00 3a 00 3a 00 73 00 70 00 6f 00 6f 00 6c 00 65 00 72 00 } //0a 00  misc::spooler
		$a_01_5 = {73 00 65 00 6b 00 75 00 72 00 6c 00 73 00 61 00 3a 00 3a 00 6c 00 69 00 76 00 65 00 73 00 73 00 70 00 } //0a 00  sekurlsa::livessp
		$a_01_6 = {73 00 65 00 6b 00 75 00 72 00 6c 00 73 00 61 00 3a 00 3a 00 73 00 73 00 70 00 } //00 00  sekurlsa::ssp
	condition:
		any of ($a_*)
 
}