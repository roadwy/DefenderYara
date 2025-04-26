
rule Backdoor_BAT_WebShell_GMB_MTB{
	meta:
		description = "Backdoor:BAT/WebShell.GMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 07 16 11 07 8e 69 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 06 09 1f 10 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 de 03 26 de 00 06 6f ?? ?? ?? 0a 2a } //10
		$a_03_1 = {41 70 70 5f 57 65 62 5f [0-16] 2e 64 6c 6c } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}