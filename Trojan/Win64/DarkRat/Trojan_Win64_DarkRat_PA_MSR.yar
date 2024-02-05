
rule Trojan_Win64_DarkRat_PA_MSR{
	meta:
		description = "Trojan:Win64/DarkRat.PA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 00 61 00 72 00 6b 00 56 00 69 00 73 00 69 00 6f 00 6e 00 20 00 52 00 41 00 54 00 } //01 00 
		$a_01_1 = {48 6f 6f 6b 50 72 6f 63 65 64 75 72 65 5f 48 6f 6f 6b 4c 6f 61 64 65 72 } //01 00 
		$a_01_2 = {44 41 52 4b 56 49 53 49 4f 4e 53 45 52 56 45 52 36 34 2e 45 58 45 } //00 00 
	condition:
		any of ($a_*)
 
}