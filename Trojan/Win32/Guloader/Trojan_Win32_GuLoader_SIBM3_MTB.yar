
rule Trojan_Win32_GuLoader_SIBM3_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBM3!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 00 41 00 52 00 41 00 4c 00 4c 00 45 00 4c 00 49 00 5a 00 49 00 4e 00 47 00 } //01 00  PARALLELIZING
		$a_03_1 = {e0 81 34 17 90 01 04 90 02 30 83 c2 04 90 02 30 81 fa 90 01 04 0f 85 90 01 04 90 02 30 ff e7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}