
rule Trojan_BAT_Bladabindi_QW_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {4d 6f 75 73 65 53 74 61 74 65 } //MouseState  03 00 
		$a_80_1 = {73 76 63 68 6f 73 74 2e 57 69 6e 64 6f 77 73 } //svchost.Windows  03 00 
		$a_80_2 = {57 65 62 43 6c 69 65 6e 74 } //WebClient  03 00 
		$a_80_3 = {43 3a 5c 55 73 65 72 73 5c 41 53 68 6f 6b 79 } //C:\Users\AShoky  03 00 
		$a_80_4 = {64 72 20 61 6c 69 } //dr ali  03 00 
		$a_80_5 = {73 76 63 68 6f 73 74 2e 70 64 62 } //svchost.pdb  03 00 
		$a_80_6 = {24 74 68 69 73 2e 54 65 78 74 } //$this.Text  00 00 
	condition:
		any of ($a_*)
 
}