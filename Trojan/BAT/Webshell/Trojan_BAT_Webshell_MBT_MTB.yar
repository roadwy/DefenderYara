
rule Trojan_BAT_Webshell_MBT_MTB{
	meta:
		description = "Trojan:BAT/Webshell.MBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 59 11 20 20 30 0e 00 00 95 5f 11 20 20 ef 05 00 00 95 61 59 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}