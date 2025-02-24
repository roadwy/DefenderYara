
rule Trojan_Win64_Lazy_GNE_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {61 f3 56 1d ?? ?? ?? ?? 1b f3 56 1d ?? ?? ?? ?? e2 f0 56 1d ?? ?? ?? ?? 2b f3 56 1d } //10
		$a_01_1 = {55 77 55 64 69 73 52 41 54 2e 70 64 62 } //1 UwUdisRAT.pdb
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}