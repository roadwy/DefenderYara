
rule Trojan_BAT_Injector_TSHP_MTB{
	meta:
		description = "Trojan:BAT/Injector.TSHP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 73 17 00 00 0a 16 73 12 00 00 0a 0a 20 00 10 00 00 8d 1a 00 00 01 0b 73 11 00 00 0a 0c 16 0d 06 07 16 20 00 10 00 00 6f ?? ?? ?? 0a 0d 09 16 31 09 08 07 16 09 6f ?? ?? ?? 0a 09 16 30 e1 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}