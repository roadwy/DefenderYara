
rule Trojan_BAT_Heracles_KAD_MTB{
	meta:
		description = "Trojan:BAT/Heracles.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {1a ec ff 23 1b ec ff 23 1a ea f9 23 1b db ef 1e 16 cd f9 1b 15 c2 ff 1a 13 bb ff 1b 16 b5 95 } //01 00 
		$a_01_1 = {55 73 65 72 73 5c 46 72 61 6e 73 65 73 63 6f 5c 44 65 73 6b 74 6f 70 5c 6b 6b 5c 6b 6c 5c 6f 62 6a 5c 44 65 62 75 67 5c 6b 6b 2e 70 64 62 } //01 00  Users\Fransesco\Desktop\kk\kl\obj\Debug\kk.pdb
		$a_01_2 = {6b 6b 2e 52 65 73 6f 75 72 63 65 73 } //00 00  kk.Resources
	condition:
		any of ($a_*)
 
}