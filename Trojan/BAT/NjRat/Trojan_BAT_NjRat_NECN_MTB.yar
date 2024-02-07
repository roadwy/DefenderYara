
rule Trojan_BAT_NjRat_NECN_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 06 6f 90 01 01 00 00 0a 11 04 05 6f 90 01 01 00 00 0a 11 04 0e 04 6f 90 01 01 00 00 0a 11 04 6f 90 01 01 00 00 0a 03 16 03 8e b7 6f 90 01 01 00 00 0a 0b 11 04 6f 90 01 01 00 00 0a 07 2a 90 00 } //01 00 
		$a_01_1 = {52 50 46 3a 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 } //01 00  RPF:SmartAssembly
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_3 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 } //01 00  EntryPoint
		$a_01_4 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //00 00  Invoke
	condition:
		any of ($a_*)
 
}