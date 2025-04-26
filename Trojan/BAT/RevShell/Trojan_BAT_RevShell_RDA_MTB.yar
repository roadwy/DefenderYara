
rule Trojan_BAT_RevShell_RDA_MTB{
	meta:
		description = "Trojan:BAT/RevShell.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 73 15 00 00 0a 0c 08 17 6f 16 00 00 0a 00 08 18 6f 17 00 00 0a 00 08 06 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}