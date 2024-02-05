
rule Trojan_Win32_Rootkit_EA_MTB{
	meta:
		description = "Trojan:Win32/Rootkit.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {71 6f 76 78 6b 5c 77 71 64 74 62 6d 61 63 2e 70 64 62 } //01 00 
		$a_01_1 = {4e 54 4f 53 4b 52 4e 4c 2e 65 78 65 } //01 00 
		$a_01_2 = {4f 6b 65 67 67 72 61 6d 20 49 6e 69 74 69 75 6c 69 7a } //01 00 
		$a_01_3 = {49 6f 44 65 6c 65 74 65 44 65 76 69 63 65 } //01 00 
		$a_01_4 = {49 6f 46 72 65 65 4d 64 6c } //00 00 
	condition:
		any of ($a_*)
 
}