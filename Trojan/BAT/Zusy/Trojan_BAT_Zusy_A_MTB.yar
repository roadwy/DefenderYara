
rule Trojan_BAT_Zusy_A_MTB{
	meta:
		description = "Trojan:BAT/Zusy.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 64 00 00 01 25 16 02 20 00 00 ff 00 5f 1f 10 63 d2 9c 25 17 02 20 00 ff 00 00 5f 1e 63 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}