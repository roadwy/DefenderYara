
rule Trojan_BAT_Oryecux_A{
	meta:
		description = "Trojan:BAT/Oryecux.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {91 61 9c 06 17 d6 0a 06 08 31 d1 } //01 00 
		$a_00_1 = {49 00 6d 00 70 00 6f 00 72 00 74 00 61 00 6e 00 74 00 2e 00 65 00 78 00 65 00 } //01 00  Important.exe
		$a_00_2 = {4d 00 65 00 6d 00 6f 00 72 00 79 00 45 00 78 00 } //00 00  MemoryEx
	condition:
		any of ($a_*)
 
}