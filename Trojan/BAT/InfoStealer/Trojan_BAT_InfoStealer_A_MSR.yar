
rule Trojan_BAT_InfoStealer_A_MSR{
	meta:
		description = "Trojan:BAT/InfoStealer.A!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 09 00 08 00 00 05 00 "
		
	strings :
		$a_01_0 = {42 24 4f f4 4f f4 4d d4 42 20 00 04 44 46 6f f6 64 46 6f } //05 00 
		$a_01_1 = {46 67 75 56 63 36 6b b0 00 05 59 93 32 } //05 00 
		$a_01_2 = {48 65 48 65 00 44 61 79 6d 00 46 54 4f 4e 4a 00 63 6f 63 6f } //01 00 
		$a_00_3 = {67 65 74 5f 49 73 41 74 74 61 63 68 65 64 } //01 00 
		$a_00_4 = {49 73 4c 6f 67 67 69 6e 67 } //01 00 
		$a_00_5 = {67 65 74 5f 49 73 41 6c 69 76 65 } //01 00 
		$a_00_6 = {42 6c 6f 63 6b 43 6f 70 79 } //01 00 
		$a_00_7 = {66 75 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}