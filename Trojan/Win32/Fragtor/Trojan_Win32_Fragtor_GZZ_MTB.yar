
rule Trojan_Win32_Fragtor_GZZ_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {56 41 d3 d6 44 8b f4 44 31 14 24 49 c1 f6 4d 45 02 f0 41 5e 40 80 ff 94 f5 41 84 c4 4d 63 d2 49 3b f6 f5 4d 03 ea e9 90 01 04 e8 90 01 04 81 f2 5d 51 69 70 90 00 } //01 00 
		$a_00_1 = {2e 69 6d 70 6f 72 74 73 } //00 00  .imports
	condition:
		any of ($a_*)
 
}