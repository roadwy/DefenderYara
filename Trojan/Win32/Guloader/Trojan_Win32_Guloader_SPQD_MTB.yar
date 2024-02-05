
rule Trojan_Win32_Guloader_SPQD_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SPQD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 64 72 65 73 73 65 6c 69 73 74 65 6e 31 } //01 00 
		$a_81_1 = {63 61 6d 70 75 73 73 65 6e 73 40 53 75 66 66 69 78 2e 64 64 31 } //01 00 
		$a_81_2 = {43 6f 72 72 61 64 65 20 41 6e 69 6d 61 64 76 65 72 73 69 6f 6e 61 6c 20 31 } //01 00 
		$a_81_3 = {41 64 72 65 73 73 65 6c 69 73 74 65 6e 30 } //00 00 
	condition:
		any of ($a_*)
 
}