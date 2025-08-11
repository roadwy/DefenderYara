
rule Trojan_BAT_Remcos_MYV_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MYV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {04 1f 09 7e 17 01 00 04 1f 6e 7e 17 01 00 04 1f 6e 93 04 5f 20 fd 00 00 00 5f 9d 5d 2c 04 18 0c 2b c0 17 2b fa 03 2b 07 03 20 ed 00 00 00 61 b4 0a 06 2a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}