
rule Trojan_BAT_MonikerLoader_SV_MTB{
	meta:
		description = "Trojan:BAT/MonikerLoader.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 07 91 1f 4d 58 0c 08 1f 78 61 0c 06 07 08 d2 9c 07 17 58 0b 07 02 8e 69 32 e5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}