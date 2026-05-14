
rule Trojan_BAT_SpyBot_AMTB{
	meta:
		description = "Trojan:BAT/SpyBot!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_80_0 = {42 65 67 67 69 6e 65 72 52 41 54 2e 70 64 62 } //BegginerRAT.pdb  2
		$a_03_1 = {42 65 67 67 69 6e 65 72 52 41 54 2e [0-0f] 2e 52 65 73 6f 75 72 63 65 73 } //2
	condition:
		((#a_80_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}