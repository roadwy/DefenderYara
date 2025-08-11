
rule Trojan_BAT_ResInject_MCF_MTB{
	meta:
		description = "Trojan:BAT/ResInject.MCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 00 38 00 31 00 6e 00 4d 00 77 00 66 00 44 00 71 00 00 15 50 00 47 00 35 00 51 00 58 00 73 00 32 00 73 00 42 00 6c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}