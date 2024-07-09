
rule Trojan_BAT_Mardom_NN_MTB{
	meta:
		description = "Trojan:BAT/Mardom.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 03 02 4b 03 04 61 05 61 58 ?? ?? ?? ?? 95 58 7e ad 08 ?? ?? 0e 06 17 59 95 58 0e 05 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}