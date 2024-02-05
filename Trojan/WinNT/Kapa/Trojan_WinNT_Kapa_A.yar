
rule Trojan_WinNT_Kapa_A{
	meta:
		description = "Trojan:WinNT/Kapa.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 38 8b ff 55 8b 75 90 01 01 81 78 04 ec 56 64 a1 75 90 01 01 81 78 08 24 01 00 00 75 90 01 01 81 78 0c 8b 75 08 3b 74 90 00 } //01 00 
		$a_01_1 = {4e 00 74 00 51 00 75 00 65 00 72 00 79 00 53 00 79 00 73 00 74 00 65 00 6d 00 49 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}