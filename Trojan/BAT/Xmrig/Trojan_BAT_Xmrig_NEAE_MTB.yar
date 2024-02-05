
rule Trojan_BAT_Xmrig_NEAE_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.NEAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {28 15 00 00 06 72 13 00 00 70 28 0f 00 00 06 28 16 00 00 06 28 0e 00 00 0a 28 02 00 00 2b 28 03 00 00 2b 13 01 } //02 00 
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 32 35 } //02 00 
		$a_01_2 = {6e 65 77 6f 6e 65 31 } //00 00 
	condition:
		any of ($a_*)
 
}