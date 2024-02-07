
rule Trojan_Win32_Smokeloader_IG_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.IG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 1c 8b c5 83 e0 03 8a 04 08 8b 4c 24 14 30 04 29 45 3b 6c 24 18 72 dc } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}