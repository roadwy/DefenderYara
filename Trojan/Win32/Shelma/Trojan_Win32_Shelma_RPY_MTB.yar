
rule Trojan_Win32_Shelma_RPY_MTB{
	meta:
		description = "Trojan:Win32/Shelma.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b d1 83 e2 03 8a 54 02 08 32 54 08 14 88 14 31 41 81 f9 0e 01 00 00 76 e7 } //00 00 
	condition:
		any of ($a_*)
 
}