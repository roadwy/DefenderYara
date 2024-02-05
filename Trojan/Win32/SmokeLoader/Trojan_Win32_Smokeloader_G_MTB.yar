
rule Trojan_Win32_Smokeloader_G_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {01 45 fc 8b 45 f4 8b 4d f8 03 c2 d3 ea 89 45 f0 03 55 d4 8b 45 f0 31 45 fc 31 55 fc } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Smokeloader_G_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00 
		$a_01_1 = {2e 70 64 62 } //01 00 
		$a_80_2 = {63 75 6a 61 6c 75 6e 6f 64 69 67 } //cujalunodig  01 00 
		$a_80_3 = {46 65 79 6f 63 69 78 75 67 6f 77 61 } //Feyocixugowa  01 00 
		$a_80_4 = {79 75 6d 65 6a 69 6e 65 66 } //yumejinef  01 00 
		$a_01_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}