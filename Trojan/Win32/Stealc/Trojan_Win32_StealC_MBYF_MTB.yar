
rule Trojan_Win32_StealC_MBYF_MTB{
	meta:
		description = "Trojan:Win32/StealC.MBYF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c0 64 89 44 24 90 01 01 83 6c 24 90 01 02 8a 4c 24 90 01 01 30 0c 1e 90 00 } //01 00 
		$a_01_1 = {6f 6d 6f 79 6f 77 65 76 00 00 00 7a 00 6f 00 72 00 75 00 6e 00 65 } //00 00 
	condition:
		any of ($a_*)
 
}