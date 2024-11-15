
rule Trojan_BAT_Webshell_AMI_MTB{
	meta:
		description = "Trojan:BAT/Webshell.AMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {70 0a 02 6f ?? 00 00 0a 6f ?? 00 00 0a 02 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 28 ?? 00 00 0a 06 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 08 08 6f ?? 00 00 0a 07 16 02 6f 0e 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 02 6f ?? 00 00 0a 6f ?? 00 00 0a 72 ?? 00 00 70 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}