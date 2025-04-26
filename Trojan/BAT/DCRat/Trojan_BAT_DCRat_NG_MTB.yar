
rule Trojan_BAT_DCRat_NG_MTB{
	meta:
		description = "Trojan:BAT/DCRat.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 09 28 b1 ?? ?? 44 14 16 9a 26 16 2d f9 02 03 02 4b 03 04 61 05 61 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}