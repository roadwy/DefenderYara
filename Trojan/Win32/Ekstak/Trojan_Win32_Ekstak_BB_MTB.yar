
rule Trojan_Win32_Ekstak_BB_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 0c 11 88 0c 90 01 01 8a 8a 90 01 04 84 c9 75 12 8b 0d 90 01 04 03 ca 03 c1 8a 0d 90 01 04 30 08 83 3d 90 01 04 03 76 03 42 eb 90 00 } //01 00 
		$a_02_1 = {60 2b f0 86 c3 83 fe 39 8d 3d 90 01 04 88 07 03 07 ba 0d 00 00 00 83 e6 3a 66 8b c3 83 f9 0e 61 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}