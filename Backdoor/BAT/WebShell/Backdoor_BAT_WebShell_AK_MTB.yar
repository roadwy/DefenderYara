
rule Backdoor_BAT_WebShell_AK_MTB{
	meta:
		description = "Backdoor:BAT/WebShell.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 08 16 1f 30 9c 08 6f ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 72 ?? ?? 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0a 02 28 ?? 00 00 0a 02 28 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 06 06 6f } //2
		$a_03_1 = {0a 07 8e 69 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 72 ?? ?? 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 02 6f ?? 00 00 0a 26 2a } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}