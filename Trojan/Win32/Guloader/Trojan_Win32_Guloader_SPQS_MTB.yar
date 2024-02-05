
rule Trojan_Win32_Guloader_SPQS_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SPQS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 65 76 69 73 69 74 73 40 54 6f 74 61 6c 69 74 65 74 65 6e 2e 46 72 69 31 20 30 } //01 00 
		$a_81_1 = {54 61 75 72 6f 6d 61 63 68 69 61 6e 20 54 73 65 6e 61 61 6c 65 73 20 31 } //01 00 
		$a_81_2 = {50 72 6f 74 68 65 74 65 6c 79 31 27 30 25 } //01 00 
		$a_81_3 = {50 72 6f 74 68 65 74 65 6c 79 30 } //00 00 
	condition:
		any of ($a_*)
 
}