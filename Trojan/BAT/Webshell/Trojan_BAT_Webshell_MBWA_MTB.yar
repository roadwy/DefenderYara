
rule Trojan_BAT_Webshell_MBWA_MTB{
	meta:
		description = "Trojan:BAT/Webshell.MBWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {6c 00 6f 00 61 00 64 00 39 00 36 00 51 00 4a 00 00 09 4c 00 6f 00 61 00 64 00 00 05 4c 00 59 } //2
		$a_01_1 = {32 00 30 00 32 00 63 00 62 00 39 00 36 00 32 00 61 00 63 00 35 00 39 00 30 00 37 00 35 00 62 00 } //1 202cb962ac59075b
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}