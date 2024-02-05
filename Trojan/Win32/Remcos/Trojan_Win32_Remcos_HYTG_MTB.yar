
rule Trojan_Win32_Remcos_HYTG_MTB{
	meta:
		description = "Trojan:Win32/Remcos.HYTG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff cc 31 00 02 6b be 00 20 ab 86 0c 44 b3 c3 } //01 00 
		$a_01_1 = {22 71 81 32 06 14 91 } //00 00 
	condition:
		any of ($a_*)
 
}