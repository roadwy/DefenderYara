
rule Trojan_Win32_GuLoader_SIBM_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {45 73 6f 74 68 79 72 6f 70 65 78 79 34 } //01 00  Esothyropexy4
		$a_03_1 = {56 f8 31 ff 90 02 04 57 90 02 05 ff d0 90 02 08 e8 90 01 04 90 02 08 31 ff 90 02 10 bb 90 01 04 90 02 08 81 f3 90 01 04 90 02 30 0b 1c 3a 90 02 08 81 f3 90 01 04 90 02 08 09 1c 38 90 02 0a 83 c7 04 90 02 05 81 ff 90 01 04 75 90 01 01 90 02 07 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}