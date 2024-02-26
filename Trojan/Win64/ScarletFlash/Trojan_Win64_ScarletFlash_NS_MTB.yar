
rule Trojan_Win64_ScarletFlash_NS_MTB{
	meta:
		description = "Trojan:Win64/ScarletFlash.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {83 3d 29 82 01 00 00 75 36 48 85 c9 75 1a e8 11 10 ff ff c7 00 90 01 04 e8 2e e7 fe ff b8 90 01 04 48 83 c4 28 90 00 } //01 00 
		$a_01_1 = {62 6c 6f 78 63 72 75 73 68 65 72 2e 70 64 62 } //00 00  bloxcrusher.pdb
	condition:
		any of ($a_*)
 
}