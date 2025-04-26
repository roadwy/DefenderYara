
rule Trojan_BAT_DCRat_A_MTB{
	meta:
		description = "Trojan:BAT/DCRat.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 3b 00 00 01 13 07 09 28 a8 01 00 0a 16 11 07 16 1a ?? ?? ?? ?? ?? 11 04 28 a8 01 00 0a 16 11 07 1a 1a ?? ?? ?? ?? ?? 11 05 28 a8 01 00 0a 16 11 07 1e 1a ?? ?? ?? ?? ?? 11 06 28 a8 01 00 0a 16 11 07 1f 0c 1a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}