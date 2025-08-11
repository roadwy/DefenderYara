
rule Backdoor_BAT_WebShell_GTB_MTB{
	meta:
		description = "Backdoor:BAT/WebShell.GTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 11 07 6f ?? 00 00 0a 13 08 11 07 6f ?? 00 00 0a 00 02 6f ?? 00 00 0a 6f ?? 00 00 0a 73 ?? 00 00 0a 08 08 6f ?? 00 00 0a 11 08 16 11 08 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 00 00 00 de 05 26 00 00 de 00 00 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}