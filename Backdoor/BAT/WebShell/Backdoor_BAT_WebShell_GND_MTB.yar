
rule Backdoor_BAT_WebShell_GND_MTB{
	meta:
		description = "Backdoor:BAT/WebShell.GND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 06 06 6f ?? ?? ?? 0a 07 16 07 8e 69 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 5d 00 00 70 6f ?? ?? ?? 0a 02 6f ?? ?? ?? 0a 26 2a } //10
		$a_01_1 = {61 73 6e 75 79 6c 62 67 61 75 62 62 } //1 asnuylbgaubb
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}