
rule Trojan_BAT_DllInject_JB_MTB{
	meta:
		description = "Trojan:BAT/DllInject.JB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 10 00 00 0a 2c 3e 72 0b 00 00 70 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}