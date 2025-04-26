
rule Trojan_BAT_Netwire_NEE_MTB{
	meta:
		description = "Trojan:BAT/Netwire.NEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 a8 00 00 0a 28 aa 00 00 0a 28 ab 00 00 0a 0b 07 28 9b 00 00 06 28 2e 00 00 0a 0c 72 f1 00 04 70 28 ac 00 00 0a 6f ad 00 00 0a } //5
		$a_01_1 = {4c 00 6f 00 61 00 64 00 } //2 Load
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}