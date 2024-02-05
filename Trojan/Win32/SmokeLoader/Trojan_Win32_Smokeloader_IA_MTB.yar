
rule Trojan_Win32_Smokeloader_IA_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.IA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {65 6f 76 77 77 6e 69 } //eovwwni  01 00 
		$a_80_1 = {6c 67 72 6d 64 79 6b } //lgrmdyk  01 00 
		$a_80_2 = {65 63 62 7a 68 72 79 } //ecbzhry  01 00 
		$a_01_3 = {53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36 } //01 00 
		$a_01_4 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f } //01 00 
		$a_01_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}