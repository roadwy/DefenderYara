
rule Trojan_Win64_Disdroth_LK_MTB{
	meta:
		description = "Trojan:Win64/Disdroth.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f 84 bd 07 00 00 48 89 c1 48 c1 e9 34 83 e1 3f 42 8a 0c 39 88 4b 01 48 83 ff 02 0f 86 ae 07 00 00 48 89 c1 48 c1 e9 2e 83 e1 3f 42 8a 0c 39 88 4b 02 48 83 ff 03 0f 84 9f 07 00 00 } //01 00 
		$a_01_1 = {4c 8b 05 e2 e3 01 00 ba 40 00 00 00 41 8b c8 83 e1 3f 2b d1 8a ca 48 8b d0 48 d3 ca 49 33 d0 4b 87 94 fe c0 86 05 00 eb 2d 4c 8b 15 b9 e3 01 00 eb b8 } //00 00 
	condition:
		any of ($a_*)
 
}