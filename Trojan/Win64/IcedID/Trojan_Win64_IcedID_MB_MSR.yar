
rule Trojan_Win64_IcedID_MB_MSR{
	meta:
		description = "Trojan:Win64/IcedID.MB!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 02 00 "
		
	strings :
		$a_81_0 = {45 6e 74 72 79 46 75 6e 63 74 31 } //02 00 
		$a_81_1 = {45 6e 74 72 79 50 6f 69 6e 74 31 } //02 00 
		$a_81_2 = {50 6c 75 67 69 6e 49 6e 69 74 } //02 00 
		$a_81_3 = {78 4b 55 7a 70 41 57 55 48 51 75 4b 45 48 68 6e 41 77 4a 34 4d 45 44 4e 34 6f 44 53 4e 70 4e 71 58 70 74 } //02 00 
		$a_81_4 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 } //02 00 
		$a_81_5 = {43 6f 6e 6e 65 63 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}