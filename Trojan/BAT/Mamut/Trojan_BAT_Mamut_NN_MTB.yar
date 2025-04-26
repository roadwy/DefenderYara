
rule Trojan_BAT_Mamut_NN_MTB{
	meta:
		description = "Trojan:BAT/Mamut.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 06 02 09 6f ?? ?? ?? ?? 03 09 6f 7f ?? ?? ?? 61 60 0a 00 09 17 58 0d 09 02 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}