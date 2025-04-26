
rule Trojan_BAT_Dcstl_NEAF_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.NEAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 6f 16 00 00 0a 00 73 17 00 00 0a 0c 08 6f 18 00 00 0a 72 13 02 00 70 6f 19 00 00 0a 00 08 6f 18 00 00 0a 17 6f 1a 00 00 0a 00 08 6f 18 00 00 0a 17 6f 1b 00 00 0a 00 08 6f 18 00 00 0a 17 6f 1c 00 00 0a 00 07 28 1e 00 00 0a 0c 2a } //10
		$a_01_1 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 4c 00 6f 00 67 00 73 00 } //2 C:\Windows\Logs
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2) >=12
 
}