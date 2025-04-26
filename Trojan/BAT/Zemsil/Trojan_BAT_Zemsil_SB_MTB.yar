
rule Trojan_BAT_Zemsil_SB_MTB{
	meta:
		description = "Trojan:BAT/Zemsil.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {1b 2c 16 07 72 1b 45 00 70 73 a5 01 00 0a 6f 60 08 00 0a 6f 53 01 00 0a 0c 73 73 04 00 0a 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}