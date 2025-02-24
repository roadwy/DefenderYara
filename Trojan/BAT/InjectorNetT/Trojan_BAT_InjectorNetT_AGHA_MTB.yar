
rule Trojan_BAT_InjectorNetT_AGHA_MTB{
	meta:
		description = "Trojan:BAT/InjectorNetT.AGHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 91 61 03 08 20 0a 02 00 00 58 20 09 02 00 00 59 1e 59 1e 58 03 8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}