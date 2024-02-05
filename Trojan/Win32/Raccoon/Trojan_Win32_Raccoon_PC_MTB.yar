
rule Trojan_Win32_Raccoon_PC_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 02 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 89 45 90 01 01 6a 00 90 02 0e 2b d8 90 02 0e 2b d8 8b 45 90 01 01 31 18 6a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}