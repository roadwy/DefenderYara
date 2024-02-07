
rule Trojan_BAT_Remcos_GL_MTB{
	meta:
		description = "Trojan:BAT/Remcos.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {2e 65 64 6f 6d 20 53 4f 44 20 6e 69 20 6e 75 72 20 65 62 20 74 6f 6e 6e 61 63 20 6d 61 72 67 6f 72 70 20 73 69 68 54 21 } //01 00  .edom SOD ni nur eb tonnac margorp sihT!
		$a_81_1 = {70 6f 77 65 72 73 68 65 6c 6c } //01 00  powershell
		$a_03_2 = {43 6f 6e 73 6f 6c 65 41 70 70 90 02 05 2e 65 78 65 90 00 } //01 00 
		$a_81_3 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_81_4 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //01 00  Form1_Load
		$a_81_5 = {63 6f 6c 65 72 2e } //01 00  coler.
		$a_81_6 = {63 72 73 72 2e } //01 00  crsr.
		$a_81_7 = {74 78 65 74 2e } //00 00  txet.
	condition:
		any of ($a_*)
 
}