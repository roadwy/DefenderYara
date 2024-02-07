
rule Trojan_Win32_AveMaria_NEDF_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.NEDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8a 0c 06 80 e9 57 80 f1 4e 80 c1 2e 80 f1 d0 80 e9 16 80 f1 56 80 e9 66 80 f1 6e 80 e9 5b 88 0c 06 40 3b 45 f0 72 d9 } //02 00 
		$a_01_1 = {2f 00 70 00 72 00 6f 00 67 00 49 00 44 00 4f 00 70 00 65 00 6e 00 } //02 00  /progIDOpen
		$a_01_2 = {2f 00 65 00 78 00 65 00 63 00 } //02 00  /exec
		$a_01_3 = {2f 00 72 00 65 00 61 00 6c 00 74 00 69 00 6d 00 65 00 } //00 00  /realtime
	condition:
		any of ($a_*)
 
}