
rule Trojan_BAT_Remcos_ACE_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ACE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0d 2b 19 06 09 6f 1b 00 00 0a 0c 08 03 61 d1 0c 07 08 6f 1c 00 00 0a 26 09 17 58 0d 09 02 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}