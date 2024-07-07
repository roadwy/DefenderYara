
rule Trojan_BAT_Stealer_NEG_MTB{
	meta:
		description = "Trojan:BAT/Stealer.NEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 09 11 05 03 11 05 09 28 5c 01 00 0a 28 5d 01 00 0a 11 05 17 d6 13 05 11 05 11 04 31 e2 } //1
		$a_01_1 = {77 00 65 00 6e 00 64 00 79 00 73 00 } //1 wendys
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}