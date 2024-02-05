
rule Trojan_Win32_RagnarLocker_A_MSR{
	meta:
		description = "Trojan:Win32/RagnarLocker.A!MSR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 41 47 4e 41 52 20 53 45 43 52 45 54 } //01 00 
		$a_01_1 = {2e 00 72 00 61 00 67 00 6e 00 61 00 72 00 5f 00 } //01 00 
		$a_01_2 = {62 00 6f 00 6f 00 74 00 73 00 65 00 63 00 74 00 2e 00 62 00 61 00 6b 00 } //00 00 
	condition:
		any of ($a_*)
 
}