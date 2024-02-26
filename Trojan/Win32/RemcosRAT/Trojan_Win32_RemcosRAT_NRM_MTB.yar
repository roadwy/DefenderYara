
rule Trojan_Win32_RemcosRAT_NRM_MTB{
	meta:
		description = "Trojan:Win32/RemcosRAT.NRM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {50 8b 03 8b 00 e8 63 f4 ff ff 50 e8 55 b3 ff ff 8b c8 8b d4 8b c6 e8 b2 e4 ff ff eb 0a 8b c6 8b 53 90 01 01 e8 ae e5 ff ff 90 00 } //01 00 
		$a_01_1 = {2a 47 68 7a 20 43 61 6e 79 6f 6e 20 53 68 61 6b 69 72 61 20 4d 61 72 67 69 6e 20 46 72 6f 6e 74 69 65 72 20 47 6f 73 73 69 70 } //00 00  *Ghz Canyon Shakira Margin Frontier Gossip
	condition:
		any of ($a_*)
 
}