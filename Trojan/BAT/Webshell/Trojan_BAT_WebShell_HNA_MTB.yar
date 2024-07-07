
rule Trojan_BAT_WebShell_HNA_MTB{
	meta:
		description = "Trojan:BAT/WebShell.HNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 00 57 00 4e 00 68 00 59 00 32 00 4d 00 77 00 4e 00 57 00 46 00 68 00 5a 00 6d 00 46 00 6d 00 4e 00 67 00 3d 00 3d 00 00 07 67 00 6f 00 76 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}