
rule Trojan_Win64_Cobaltstrike_RI_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8d 95 7c ff ff ff 48 8b 45 f8 49 89 d1 41 b8 20 00 00 00 ba 18 00 00 00 48 89 c1 48 8b 05 90 01 04 ff d0 85 c0 0f 94 c0 84 c0 74 24 90 00 } //01 00 
		$a_01_1 = {2f 00 62 00 65 00 61 00 63 00 6f 00 6e 00 2e 00 62 00 69 00 6e 00 } //00 00  /beacon.bin
	condition:
		any of ($a_*)
 
}