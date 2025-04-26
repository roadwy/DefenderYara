
rule Backdoor_BAT_WebShell_GNS_MTB{
	meta:
		description = "Backdoor:BAT/WebShell.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 00 06 16 6f ?? ?? ?? 0a 00 06 28 ?? ?? ?? 0a 0b 07 6f ?? ?? ?? 0a 0c 08 6f ?? ?? ?? 0a 0d 08 6f ?? ?? ?? 0a 00 09 13 04 2b 00 11 04 2a } //5
		$a_01_1 = {20 c8 85 6a 9f 0a 2b 00 06 2a } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}