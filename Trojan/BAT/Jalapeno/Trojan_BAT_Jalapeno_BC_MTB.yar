
rule Trojan_BAT_Jalapeno_BC_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 2a 06 20 05 00 00 00 64 0a 02 06 20 8f 56 5b 65 60 0a 7b dd 01 00 04 b6 06 20 42 44 5f 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}