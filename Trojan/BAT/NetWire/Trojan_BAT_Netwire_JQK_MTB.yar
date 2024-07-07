
rule Trojan_BAT_Netwire_JQK_MTB{
	meta:
		description = "Trojan:BAT/Netwire.JQK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {91 7e 18 00 00 04 } //1
		$a_01_1 = {7e 18 00 00 04 8e b7 5d 91 61 9c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}