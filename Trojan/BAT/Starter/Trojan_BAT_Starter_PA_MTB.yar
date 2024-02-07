
rule Trojan_BAT_Starter_PA_MTB{
	meta:
		description = "Trojan:BAT/Starter.PA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 54 00 65 00 6d 00 70 00 5c 00 55 00 53 00 42 00 33 00 4d 00 4f 00 4e 00 2e 00 65 00 78 00 65 00 } //01 00  \Temp\USB3MON.exe
		$a_01_1 = {5c 00 54 00 65 00 6d 00 70 00 5c 00 66 00 6f 00 75 00 6e 00 64 00 2e 00 30 00 30 00 30 00 } //01 00  \Temp\found.000
		$a_01_2 = {66 6f 75 6e 64 2e 30 30 30 2e 65 78 65 } //01 00  found.000.exe
		$a_01_3 = {7a 61 77 72 48 4a 66 } //00 00  zawrHJf
	condition:
		any of ($a_*)
 
}