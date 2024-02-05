
rule Trojan_Win32_Fareit_RQS_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RQS!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //02 00 
		$a_01_1 = {54 00 67 00 4d 00 48 00 68 00 77 00 5a 00 75 00 5a 00 74 00 63 00 57 00 49 00 6a 00 56 00 67 00 6f 00 77 00 4d 00 77 00 70 00 6a 00 63 00 61 00 30 00 64 00 42 00 4b 00 31 00 32 00 48 00 31 00 31 00 36 00 37 00 } //00 00 
	condition:
		any of ($a_*)
 
}