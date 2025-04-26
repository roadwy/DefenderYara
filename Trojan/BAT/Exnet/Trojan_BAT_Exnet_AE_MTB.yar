
rule Trojan_BAT_Exnet_AE_MTB{
	meta:
		description = "Trojan:BAT/Exnet.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 1e 00 00 0a 0a 02 6f d5 00 00 0a 2c 2a 28 1e 00 00 0a 06 28 d6 00 00 0a 0b 12 01 28 d7 00 00 0a 03 6c 36 07 02 6f d8 00 00 0a 2a 20 e8 03 00 00 28 c5 00 00 0a 2b ce } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}