
rule Trojan_Win32_IcedId_SIBM_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {49 6e 64 75 73 74 72 79 2e 70 64 62 } //01 00 
		$a_03_1 = {58 89 44 24 90 01 01 8b 3b 90 02 50 8b 44 24 90 1b 00 81 c7 90 01 04 89 3b 83 c3 04 48 90 02 10 89 44 24 90 1b 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}