
rule Trojan_Win32_Tnega_MC_MTB{
	meta:
		description = "Trojan:Win32/Tnega.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 03 43 81 c2 3a 82 84 37 81 c7 de 6b ea e2 39 f3 75 90 01 01 09 d2 09 d2 c3 90 0a 26 00 b8 90 01 04 47 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Tnega_MC_MTB_2{
	meta:
		description = "Trojan:Win32/Tnega.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 00 6f 00 76 00 65 00 64 00 6b 00 61 00 74 00 61 00 6c 00 6f 00 67 00 31 00 } //01 00 
		$a_01_1 = {66 00 65 00 64 00 74 00 65 00 67 00 72 00 65 00 76 00 65 00 72 00 } //01 00 
		$a_01_2 = {50 00 72 00 6f 00 64 00 75 00 6b 00 74 00 75 00 64 00 76 00 69 00 6b 00 6c 00 65 00 } //01 00 
		$a_81_3 = {54 75 72 6b 6f 6d 37 } //01 00 
		$a_81_4 = {42 69 6e 72 66 6f 72 6d 73 33 } //01 00 
		$a_81_5 = {53 75 72 72 65 61 6c 69 } //01 00 
		$a_81_6 = {43 61 64 61 76 65 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}