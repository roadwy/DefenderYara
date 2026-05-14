
rule Trojan_BAT_NjRAT_ZHI_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.ZHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 02 8e b7 17 59 0c 0b 2b 0d 02 07 02 07 91 1d 61 d2 9c 07 1d 58 0b 07 08 31 ef 02 2a } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}