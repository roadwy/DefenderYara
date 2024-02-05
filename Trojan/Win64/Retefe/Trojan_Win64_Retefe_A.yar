
rule Trojan_Win64_Retefe_A{
	meta:
		description = "Trojan:Win64/Retefe.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 3a 5c 4a 4f 42 5c 70 72 6f 6a 65 63 74 73 5c 43 2b 2b 5c 4a 53 4c 6f 61 64 65 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 4a 53 4c 6f 61 64 65 72 2e 70 64 62 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}