
rule Trojan_Win32_DragonSpy_VC_MTB{
	meta:
		description = "Trojan:Win32/DragonSpy.VC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 73 76 6d 5c 73 76 6d 2e 65 78 65 } //01 00 
		$a_81_1 = {70 72 6f 63 65 73 73 2e 74 78 74 } //01 00 
		$a_03_2 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 49 00 4d 00 20 00 90 02 0a 2e 00 65 00 78 00 65 00 20 00 2f 00 46 00 90 00 } //01 00 
		$a_03_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 90 02 0a 2e 65 78 65 20 2f 46 90 00 } //01 00 
		$a_81_4 = {77 77 77 2e 6e 69 6e 67 7a 68 69 64 61 74 61 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}