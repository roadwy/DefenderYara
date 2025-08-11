
rule Trojan_BAT_Jalapeno_BL_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 02 72 d5 27 00 70 6f e9 00 00 0a 2c 3e 06 02 6f ea 00 00 0a 0b 07 16 73 eb 00 00 0a 0c 73 ec 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}