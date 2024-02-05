
rule Trojan_MacOS_LooseMaque_A_MTB{
	meta:
		description = "Trojan:MacOS/LooseMaque.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 74 66 6a 2e 6e 65 74 2f 6c 6f 73 65 6c 6f 73 65 2f 68 69 67 68 73 63 6f 72 65 2e 70 68 70 } //01 00 
		$a_00_1 = {2f 61 70 70 73 2f 7a 61 63 68 2f 76 69 72 75 73 2f } //01 00 
		$a_00_2 = {6b 69 6c 6c 69 6e 67 20 69 6e 20 6c 6f 73 65 2f 6c 6f 73 65 20 64 65 6c 65 74 65 73 20 79 6f 75 72 20 66 69 6c 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}