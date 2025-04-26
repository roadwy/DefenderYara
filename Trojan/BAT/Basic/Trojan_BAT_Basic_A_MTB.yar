
rule Trojan_BAT_Basic_A_MTB{
	meta:
		description = "Trojan:BAT/Basic.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 0a 02 06 16 1a 6f a2 00 00 0a 26 06 16 28 63 00 00 0a 0b 07 8d 46 00 00 01 0c 02 08 16 07 6f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}