
rule Trojan_Win32_Androm_EH_MTB{
	meta:
		description = "Trojan:Win32/Androm.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 6f 6a 6f 4a 4c 64 6a 6e 73 41 32 63 6c 74 } //01 00 
		$a_01_1 = {71 54 70 76 69 33 76 66 59 46 7a } //01 00 
		$a_01_2 = {32 72 66 6b 69 6e 64 79 73 61 64 76 6e 71 77 33 6e 65 72 61 73 64 66 } //01 00 
		$a_01_3 = {45 49 64 45 6d 61 69 6c 50 61 72 73 65 } //01 00 
		$a_01_4 = {47 65 74 41 63 63 65 70 74 45 78 53 6f 63 6b 61 64 64 72 73 } //00 00 
	condition:
		any of ($a_*)
 
}