
rule Trojan_BAT_NjRAT_KAAJ_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.KAAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 07 95 58 6e 20 ff 00 00 00 6a 5f 69 95 61 d2 9c 09 17 58 0d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}