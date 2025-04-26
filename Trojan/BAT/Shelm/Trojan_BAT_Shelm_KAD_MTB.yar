
rule Trojan_BAT_Shelm_KAD_MTB{
	meta:
		description = "Trojan:BAT/Shelm.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 11 09 11 11 91 11 0b 28 ?? 00 00 0a 61 d2 9c 11 11 17 58 13 11 11 11 09 8e 69 32 e2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}