
rule Trojan_BAT_Vahodon_D{
	meta:
		description = "Trojan:BAT/Vahodon.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {6e 00 6a 00 2d 00 71 00 38 00 } //01 00  nj-q8
		$a_00_1 = {73 00 65 00 6e 00 64 00 66 00 69 00 6c 00 65 00 } //01 00  sendfile
		$a_01_2 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 66 00 69 00 6c 00 65 00 7c 00 7c 00 } //01 00  downloadfile||
		$a_01_3 = {00 53 42 00 42 53 00 } //00 00 
		$a_00_4 = {5d 04 00 } //00 de 
	condition:
		any of ($a_*)
 
}