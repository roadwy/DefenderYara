
rule Trojan_BAT_SmokeLoader_LL_MTB{
	meta:
		description = "Trojan:BAT/SmokeLoader.LL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 58 4a 61 d2 61 d2 52 90 01 04 fe 0c 05 00 90 01 05 25 47 fe 0c 90 01 06 91 61 d2 52 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}