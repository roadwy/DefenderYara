
rule Trojan_Win32_Emotet_PEA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 e1 ff 00 00 00 03 c1 b9 90 01 04 99 f7 f9 8a 03 83 c4 0c 8a 54 14 90 01 01 32 c2 88 03 90 09 04 00 8a 44 34 90 00 } //01 00 
		$a_81_1 = {4e 41 4f 54 38 62 78 6a 37 68 63 37 6f 41 75 41 51 71 6c 4c 7e 57 56 48 } //00 00 
	condition:
		any of ($a_*)
 
}