
rule Trojan_Win64_ScarletFlash_NS_MTB{
	meta:
		description = "Trojan:Win64/ScarletFlash.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 3d 29 82 01 00 00 75 36 48 85 c9 75 1a e8 11 10 ff ff c7 00 ?? ?? ?? ?? e8 2e e7 fe ff b8 ?? ?? ?? ?? 48 83 c4 28 } //5
		$a_01_1 = {62 6c 6f 78 63 72 75 73 68 65 72 2e 70 64 62 } //1 bloxcrusher.pdb
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}