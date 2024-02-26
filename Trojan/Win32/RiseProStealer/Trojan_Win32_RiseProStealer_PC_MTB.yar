
rule Trojan_Win32_RiseProStealer_PC_MTB{
	meta:
		description = "Trojan:Win32/RiseProStealer.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b ca 23 ce b8 90 02 04 3b ce ba 90 02 04 0f 43 ce c1 e1 02 e8 90 02 04 8b 55 fc 24 0f 8d 4a 90 01 01 32 c1 32 c3 88 44 15 90 01 01 42 89 55 fc 83 fa 90 01 01 72 90 01 01 0f 57 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}