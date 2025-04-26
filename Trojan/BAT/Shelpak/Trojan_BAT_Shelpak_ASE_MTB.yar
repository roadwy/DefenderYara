
rule Trojan_BAT_Shelpak_ASE_MTB{
	meta:
		description = "Trojan:BAT/Shelpak.ASE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {a2 0a 16 0b 2b 18 06 07 9a 28 01 00 00 06 0c 12 02 28 10 00 00 0a 2c 02 17 2a 07 17 58 0b 07 06 8e 69 32 e2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}