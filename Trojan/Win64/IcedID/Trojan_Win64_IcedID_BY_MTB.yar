
rule Trojan_Win64_IcedID_BY_MTB{
	meta:
		description = "Trojan:Win64/IcedID.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2b d1 8a ca 48 8b d0 48 d3 ca 49 33 d0 4b 87 94 fe b8 6b 02 00 eb 2d } //0a 00 
		$a_02_1 = {41 8b c2 b9 40 00 00 00 83 e0 3f 2b c8 48 d3 cf 49 33 fa 4b 87 bc fe 90 01 04 33 c0 48 8b 5c 24 50 48 8b 6c 24 58 48 8b 74 24 60 48 83 c4 20 41 5f 41 5e 41 5d 41 5c 5f c3 90 00 } //01 00 
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}