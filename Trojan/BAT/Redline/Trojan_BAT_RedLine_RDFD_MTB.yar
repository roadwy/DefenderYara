
rule Trojan_BAT_RedLine_RDFD_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 42 00 00 0a 28 43 00 00 0a 28 45 00 00 0a fe 0e dc 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}