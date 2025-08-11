
rule Backdoor_BAT_WebShell_GTQ_MTB{
	meta:
		description = "Backdoor:BAT/WebShell.GTQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 02 6f ?? 00 00 0a 6f ?? 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 0a 0d d0 ?? 00 00 01 28 ?? 00 00 0a 72 } //10
		$a_03_1 = {41 70 70 5f 57 65 62 5f [0-16] 2e 64 6c 6c } //1
		$a_01_2 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}